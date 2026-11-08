#!/usr/bin/env python3
"""Demo only: edit a stored report the way an attacker with database access would.

Rewrites the verdict to low_risk AND recomputes the hash stored beside it, so the local /verify endpoint still passes.
Only the comparison against the on-chain hash can catch it.

  .venv/bin/python scripts/tamper_report.py <report_id>            # tamper
  .venv/bin/python scripts/tamper_report.py <report_id> --restore  # undo
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app import store  # noqa: E402
from app.schemas import Report, RiskLevel  # noqa: E402


def _write(report: Report) -> None:
    with store._lock:
        store._db.execute("UPDATE reports SET risk_level=?, report_hash=?, body=? WHERE report_id=?",
                          (report.risk_level.value, report.report_hash, report.model_dump_json(), report.report_id))
        store._db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report_id")
    parser.add_argument("--restore", action="store_true", help="put back the original report")
    args = parser.parse_args()

    backup = store.DB_PATH.parent / f"tamper-backup-{args.report_id}.json"
    if args.restore:
        if not backup.exists():
            print(f"No backup found at {backup}", file=sys.stderr)
            return 1
        _write(Report.model_validate_json(backup.read_text()))
        backup.unlink()
        print(f"Restored {args.report_id}")
        return 0

    report = store.get(args.report_id)
    if report is None:
        print(f"Report {args.report_id} not found in {store.DB_PATH}", file=sys.stderr)
        return 1
    if backup.exists():
        print(f"{args.report_id} is already tampered; run with --restore first", file=sys.stderr)
        return 1

    backup.write_text(report.model_dump_json())
    edited = report.model_copy(update={"risk_level": RiskLevel.LOW, "risk_score": 0})
    edited.report_hash = store.compute_hash(edited)
    _write(edited)
    print(f"Tampered {args.report_id}: {report.risk_level.value} -> {edited.risk_level.value}")
    print(f"Stored hash rewritten to {edited.report_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
