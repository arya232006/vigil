"""Report storage (Postgres when DATABASE_URL is set, SQLite otherwise) + an indicator index used for correlation.

A report's owner is a database column and deliberately not part of the report body, so it never enters the hash that
is committed on-chain. owner_id NULL means a guest's report: there is no account to restrict it to.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path

from .schemas import Report

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = Path(os.getenv("DB_PATH", Path(__file__).resolve().parent.parent / "data" / "reports.db"))


class _SqliteDb:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        try:
            path.chmod(0o600)                       # reports hold users' messages; the WAL files inherit this mode
        except OSError:
            pass
        self._lock = threading.Lock()

    def query(self, sql: str, params: tuple | list = ()) -> list[tuple]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            self._conn.commit()
            return rows

    def transaction(self, *steps: tuple[str, list]) -> None:
        """Each step is (sql, rows); the sql runs once per row and all steps commit together."""
        with self._lock:
            for sql, rows in steps:
                self._conn.executemany(sql, rows)
            self._conn.commit()


class _PostgresDb:
    def __init__(self, url: str):
        from psycopg_pool import ConnectionPool
        # Prepared statements are off because Neon's pooled endpoint is PgBouncer. check= replaces connections that
        # were dropped while idle (Neon suspends quiet databases).
        self._pool = ConnectionPool(url, min_size=1, max_size=int(os.getenv("DB_POOL_MAX", "8")), open=True, timeout=20,
                                    check=ConnectionPool.check_connection, kwargs={"prepare_threshold": None})
        atexit.register(self._pool.close)

    def query(self, sql: str, params: tuple | list = ()) -> list[tuple]:
        with self._pool.connection() as conn:
            cur = conn.execute(sql.replace("?", "%s"), params)
            return cur.fetchall() if cur.description else []

    def transaction(self, *steps: tuple[str, list]) -> None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            for sql, rows in steps:
                if rows:
                    cur.executemany(sql.replace("?", "%s"), rows)


_db: _SqliteDb | _PostgresDb = _PostgresDb(DATABASE_URL) if DATABASE_URL else _SqliteDb(DB_PATH)

for _statement in (
    """CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        analyzed_at TEXT NOT NULL,
        input_type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        report_hash TEXT NOT NULL,
        body TEXT NOT NULL,
        owner_id TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS indicators (
        report_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ind ON indicators(kind, value)",
    """CREATE TABLE IF NOT EXISTS anchors (
        report_id TEXT NOT NULL,
        chain_id BIGINT NOT NULL,
        contract_address TEXT NOT NULL,
        registry_id BIGINT NOT NULL,
        tx_hash TEXT NOT NULL,
        block_number BIGINT NOT NULL,
        report_hash TEXT NOT NULL,
        indicator_hash TEXT NOT NULL,
        reporter TEXT NOT NULL,
        anchored_at TEXT NOT NULL,
        PRIMARY KEY (report_id, chain_id, contract_address)
    )""",
    """CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        google_sub TEXT UNIQUE
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
):
    _db.query(_statement)
if isinstance(_db, _SqliteDb) and "owner_id" not in [r[1] for r in _db.query("PRAGMA table_info(reports)")]:
    _db.query("ALTER TABLE reports ADD COLUMN owner_id TEXT")      # databases created before accounts existed
_db.query("CREATE INDEX IF NOT EXISTS idx_reports_owner ON reports(owner_id, analyzed_at)")

_ANCHOR_COLUMNS = ("report_id", "chain_id", "contract_address", "registry_id", "tx_hash", "block_number",
                   "report_hash", "indicator_hash", "reporter", "anchored_at")
_ANCHOR_KEY = ("report_id", "chain_id", "contract_address")


def canonical_json(report: Report) -> str:
    data = report.model_dump(mode="json", exclude={"report_hash"})
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(report: Report) -> str:
    return "0x" + hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()


RETENTION_DAYS = float(os.getenv("REPORT_RETENTION_DAYS", "0"))     # 0 = keep forever (default for the demo)


def purge_expired() -> int:
    """Delete reports (and their indicators) older than REPORT_RETENTION_DAYS. Hashes already anchored on-chain
    stay there; only our copy of the report (including any pasted message text) is removed."""
    if RETENTION_DAYS <= 0:
        return 0
    import datetime as _dt
    cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
    ids = [(r[0],) for r in _db.query("SELECT report_id FROM reports WHERE analyzed_at < ?", (cutoff,))]
    _db.transaction(("DELETE FROM indicators WHERE report_id=?", ids), ("DELETE FROM reports WHERE report_id=?", ids))
    return len(ids)


def save(report: Report, indicators: list[tuple[str, str]], owner_id: str | None = None) -> None:
    purge_expired()
    _db.transaction(
        ("INSERT INTO reports (report_id, analyzed_at, input_type, risk_level, report_hash, body, owner_id) "
         "VALUES (?,?,?,?,?,?,?) ON CONFLICT (report_id) DO UPDATE SET analyzed_at=excluded.analyzed_at, "
         "input_type=excluded.input_type, risk_level=excluded.risk_level, report_hash=excluded.report_hash, "
         "body=excluded.body, owner_id=excluded.owner_id",
         [(report.report_id, report.analyzed_at, report.input_type, report.risk_level.value, report.report_hash,
           report.model_dump_json(), owner_id)]),
        ("INSERT INTO indicators VALUES (?,?,?)", [(report.report_id, k, v) for k, v in set(indicators)]),
    )


def create_user(email: str, password_hash: str, created_at: int) -> str | None:
    """The new user's id, or None if the email is taken. The database decides, so simultaneous sign-ups can't both win."""
    rows = _db.query("INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?) "
                     "ON CONFLICT (email) DO NOTHING RETURNING id",
                     (f"usr_{uuid.uuid4().hex}", email, password_hash, created_at))
    return rows[0][0] if rows else None


def find_user(email: str) -> tuple[str, str] | None:
    rows = _db.query("SELECT id, password_hash FROM users WHERE email=?", (email,))
    return (rows[0][0], rows[0][1]) if rows else None


def google_user(sub: str, email: str, created_at: int) -> str | None:
    """The account for a verified Google identity, creating or linking one. None if the email belongs to another Google
    identity. Vigil doesn't verify emails at sign-up, so anyone could have registered this address first: linking removes
    the password and every session, which locks out whoever did."""
    for _ in range(2):                                      # a second pass settles two simultaneous first sign-ins
        rows = _db.query("SELECT id FROM users WHERE google_sub=?", (sub,))
        if rows:
            return rows[0][0]
        rows = _db.query("SELECT id, google_sub FROM users WHERE email=?", (email,))
        if rows:
            if rows[0][1] is not None:
                return None
            _db.query("UPDATE users SET google_sub=?, password_hash='' WHERE id=?", (sub, rows[0][0]))
            _db.query("DELETE FROM sessions WHERE user_id=?", (rows[0][0],))
            return rows[0][0]
        rows = _db.query("INSERT INTO users (id, email, password_hash, created_at, google_sub) VALUES (?,?,'',?,?) "
                         "ON CONFLICT DO NOTHING RETURNING id", (f"usr_{uuid.uuid4().hex}", email, created_at, sub))
        if rows:
            return rows[0][0]
    return None


def set_password_hash(user_id: str, password_hash: str) -> None:
    _db.query("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))


def create_session(token_hash: str, user_id: str, created_at: int, expires_at: int) -> None:
    _db.query("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
              (token_hash, user_id, created_at, expires_at))


def session_user(token_hash: str, now: int) -> tuple[str, str] | None:
    rows = _db.query("SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id "
                     "WHERE s.token_hash=? AND s.expires_at > ?", (token_hash, now))
    return (rows[0][0], rows[0][1]) if rows else None


def delete_session(token_hash: str) -> None:
    _db.query("DELETE FROM sessions WHERE token_hash=?", (token_hash,))


def purge_sessions(now: int) -> None:
    _db.query("DELETE FROM sessions WHERE expires_at <= ?", (now,))


def get(report_id: str) -> Report | None:
    rows = _db.query("SELECT body FROM reports WHERE report_id=?", (report_id,))
    return Report.model_validate_json(rows[0][0]) if rows else None


def get_for_viewer(report_id: str, viewer_id: str | None) -> Report | None:
    """The report if `viewer_id` may read it: guest reports are open to anyone with the link, owned reports only to
    their owner. Not found and not allowed look the same, so a report's existence is not revealed."""
    rows = _db.query("SELECT body, owner_id FROM reports WHERE report_id=?", (report_id,))
    if not rows or rows[0][1] not in (None, viewer_id):
        return None
    return Report.model_validate_json(rows[0][0])


def save_anchor(anchor: dict) -> None:
    updates = ",".join(f"{c}=excluded.{c}" for c in _ANCHOR_COLUMNS if c not in _ANCHOR_KEY)
    _db.transaction((f"INSERT INTO anchors ({','.join(_ANCHOR_COLUMNS)}) VALUES ({','.join('?' * len(_ANCHOR_COLUMNS))}) "
                     f"ON CONFLICT ({','.join(_ANCHOR_KEY)}) DO UPDATE SET {updates}",
                     [[anchor[c] for c in _ANCHOR_COLUMNS]]))


def get_anchor(report_id: str, chain_id: int, contract_address: str) -> dict | None:
    rows = _db.query(f"SELECT {','.join(_ANCHOR_COLUMNS)} FROM anchors "
                     "WHERE report_id=? AND chain_id=? AND contract_address=?",
                     (report_id, chain_id, contract_address))
    return dict(zip(_ANCHOR_COLUMNS, rows[0])) if rows else None


def list_reports(owner_id: str, limit: int = 50) -> list[dict]:
    rows = _db.query(
        "SELECT report_id, analyzed_at, input_type, risk_level, report_hash, body FROM reports "
        "WHERE owner_id=? ORDER BY analyzed_at DESC LIMIT ?",
        (owner_id, limit),
    )
    out = []
    for rid, at, typ, lvl, h, body in rows:
        inp = json.loads(body).get("input", "")
        out.append({
            "report_id": rid, "analyzed_at": at, "input_type": typ, "risk_level": lvl,
            "report_hash": h, "input_preview": inp[:120],
        })
    return out


def find_related(indicators: list[tuple[str, str]], exclude_id: str | None = None) -> dict[str, list[str]]:
    """Return {report_id: ["kind:value", ...]} for stored reports sharing any indicator."""
    related: dict[str, list[str]] = {}
    for kind, value in set(indicators):
        for (rid,) in _db.query("SELECT DISTINCT report_id FROM indicators WHERE kind=? AND value=?", (kind, value)):
            if rid != exclude_id:
                related.setdefault(rid, []).append(f"{kind}:{value}")
    return related


def summary(report_id: str) -> tuple[str, str, str | None] | None:
    """(risk_level, analyzed_at, owner_id)"""
    rows = _db.query("SELECT risk_level, analyzed_at, owner_id FROM reports WHERE report_id=?", (report_id,))
    return rows[0] if rows else None


def recent_messages(limit: int = 300) -> list[tuple[str, str]]:
    rows = _db.query("SELECT report_id, body FROM reports WHERE input_type='message' ORDER BY analyzed_at DESC LIMIT ?",
                     (limit,))
    return [(rid, json.loads(body).get("input", "")) for rid, body in rows]


def stats(owner_id: str) -> dict:
    levels = dict(_db.query("SELECT risk_level, COUNT(*) FROM reports WHERE owner_id=? GROUP BY risk_level", (owner_id,)))
    types = dict(_db.query("SELECT input_type, COUNT(*) FROM reports WHERE owner_id=? GROUP BY input_type", (owner_id,)))
    top = {}
    for kind in ("domain", "redirect", "entity", "upi", "phone", "ip"):
        top[kind] = [{"value": v, "reports": n} for v, n in _db.query(
            "SELECT i.value, COUNT(DISTINCT i.report_id) n FROM indicators i JOIN reports r ON r.report_id=i.report_id "
            "WHERE i.kind=? AND r.owner_id=? AND r.risk_level IN ('suspicious','high_risk','confirmed_malicious') "
            "GROUP BY i.value HAVING COUNT(DISTINCT i.report_id)>1 ORDER BY n DESC LIMIT 10", (kind, owner_id))]
    total = sum(levels.values())
    return {"total_reports": total, "by_risk_level": levels, "by_input_type": types,
            "recurring_indicators": top}
