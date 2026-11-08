"""SQLite storage for reports + an indicator index used for correlation."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

from .schemas import Report

DB_PATH = Path(os.getenv("DB_PATH", Path(__file__).resolve().parent.parent / "data" / "reports.db"))
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    return c


_db = _conn()
_db.executescript(
    """
    CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        analyzed_at TEXT NOT NULL,
        input_type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        report_hash TEXT NOT NULL,
        body TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS indicators (
        report_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ind ON indicators(kind, value);
    CREATE TABLE IF NOT EXISTS anchors (
        report_id TEXT NOT NULL,
        chain_id INTEGER NOT NULL,
        contract_address TEXT NOT NULL,
        registry_id INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        block_number INTEGER NOT NULL,
        report_hash TEXT NOT NULL,
        indicator_hash TEXT NOT NULL,
        reporter TEXT NOT NULL,
        anchored_at TEXT NOT NULL,
        PRIMARY KEY (report_id, chain_id, contract_address)
    );
    """
)
_ANCHOR_COLUMNS = ("report_id", "chain_id", "contract_address", "registry_id", "tx_hash", "block_number",
                   "report_hash", "indicator_hash", "reporter", "anchored_at")


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
    with _lock:
        ids = [r[0] for r in _db.execute("SELECT report_id FROM reports WHERE analyzed_at < ?", (cutoff,))]
        _db.executemany("DELETE FROM indicators WHERE report_id=?", [(i,) for i in ids])
        _db.executemany("DELETE FROM reports WHERE report_id=?", [(i,) for i in ids])
        _db.commit()
    return len(ids)


def save(report: Report, indicators: list[tuple[str, str]]) -> None:
    purge_expired()
    with _lock:
        _db.execute(
            "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?)",
            (
                report.report_id,
                report.analyzed_at,
                report.input_type,
                report.risk_level.value,
                report.report_hash,
                report.model_dump_json(),
            ),
        )
        _db.executemany(
            "INSERT INTO indicators VALUES (?,?,?)",
            [(report.report_id, k, v) for k, v in set(indicators)],
        )
        _db.commit()


def get(report_id: str) -> Report | None:
    row = _db.execute("SELECT body FROM reports WHERE report_id=?", (report_id,)).fetchone()
    return Report.model_validate_json(row[0]) if row else None


def save_anchor(anchor: dict) -> None:
    with _lock:
        _db.execute(f"INSERT OR REPLACE INTO anchors ({','.join(_ANCHOR_COLUMNS)}) VALUES "
                    f"({','.join('?' * len(_ANCHOR_COLUMNS))})", [anchor[c] for c in _ANCHOR_COLUMNS])
        _db.commit()


def get_anchor(report_id: str, chain_id: int, contract_address: str) -> dict | None:
    row = _db.execute(f"SELECT {','.join(_ANCHOR_COLUMNS)} FROM anchors "
                      "WHERE report_id=? AND chain_id=? AND contract_address=?",
                      (report_id, chain_id, contract_address)).fetchone()
    return dict(zip(_ANCHOR_COLUMNS, row)) if row else None


def list_reports(limit: int = 50) -> list[dict]:
    rows = _db.execute(
        "SELECT report_id, analyzed_at, input_type, risk_level, report_hash, body FROM reports "
        "ORDER BY analyzed_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
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
        for (rid,) in _db.execute(
            "SELECT DISTINCT report_id FROM indicators WHERE kind=? AND value=?", (kind, value)
        ):
            if rid != exclude_id:
                related.setdefault(rid, []).append(f"{kind}:{value}")
    return related


def summary(report_id: str) -> tuple[str, str] | None:
    row = _db.execute("SELECT risk_level, analyzed_at FROM reports WHERE report_id=?", (report_id,)).fetchone()
    return (row[0], row[1]) if row else None


def recent_messages(limit: int = 300) -> list[tuple[str, str]]:
    rows = _db.execute("SELECT report_id, body FROM reports WHERE input_type='message' ORDER BY analyzed_at DESC LIMIT ?",
                       (limit,)).fetchall()
    return [(rid, json.loads(body).get("input", "")) for rid, body in rows]


def stats() -> dict:
    levels = dict(_db.execute("SELECT risk_level, COUNT(*) FROM reports GROUP BY risk_level").fetchall())
    types = dict(_db.execute("SELECT input_type, COUNT(*) FROM reports GROUP BY input_type").fetchall())
    top = {}
    for kind in ("domain", "entity", "upi", "phone", "ip"):
        top[kind] = [{"value": v, "reports": n} for v, n in _db.execute(
            "SELECT i.value, COUNT(DISTINCT i.report_id) n FROM indicators i JOIN reports r ON r.report_id=i.report_id "
            "WHERE i.kind=? AND r.risk_level IN ('suspicious','high_risk','confirmed_malicious') "
            "GROUP BY i.value HAVING n>1 ORDER BY n DESC LIMIT 10", (kind,)).fetchall()]
    total = sum(levels.values())
    return {"total_reports": total, "by_risk_level": levels, "by_input_type": types,
            "recurring_indicators": top}
