"""Task B data: teacher-written, finding-grounded explanations for real pipeline reports (+ domain-swapped variants).
Output: data/distill/explain.jsonl  [{"user": ..., "assistant": ...}]"""
from __future__ import annotations

import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
sys.path.insert(0, str(ROOT))
import teacher  # noqa: E402
from app.ml.s2_prompt import EXPLAIN_SYSTEM  # noqa: E402
from app.ml.system2 import EXPLAIN_SCHEMA  # noqa: E402
from app.pipeline import _compact  # noqa: E402
from app.schemas import Report  # noqa: E402

random.seed(5)
FAKE = ["secure-paypa1.com", "hdfc-kyc-verify.top", "amaz0n-refunds.shop", "sbi-yono-update.in-net.co",
        "netflix-billing-help.xyz", "icici-rewardz.co.in", "irctc-refund.online", "jio-ekyc.support",
        "example-store.in", "my-blog-site.net", "university-portal.edu.in", "cityhospital.org"]


def variants(rep: Report, n: int) -> list[tuple[str, str]]:
    base = _compact(rep.findings)
    if not base:
        return []
    reg = rep.target.registered_domain if rep.target and rep.target.registered_domain else None
    out = [(rep.input, json.dumps(base, ensure_ascii=False))]
    for d in random.sample(FAKE, min(n - 1, len(FAKE))):
        s = json.dumps(base, ensure_ascii=False)
        subj = rep.input
        if reg:
            s, subj = s.replace(reg, d), subj.replace(reg, d)
        out.append((subj, s))
    return out


def gen(subject: str, findings_json: str, level: str) -> dict | None:
    findings = json.loads(findings_json)
    user = "<findings>\n" + json.dumps({"subject": subject[:300], "risk_level": level, "findings": findings},
                                       ensure_ascii=False) + "\n</findings>"
    try:
        out = json.loads(teacher.chat(EXPLAIN_SYSTEM, user, EXPLAIN_SCHEMA, temperature=0.2, num_predict=700))
    except Exception:
        return None
    valid = {f["id"] for f in findings}
    kps = [{"text": k["text"], "finding_ids": [i for i in k.get("finding_ids", []) if i in valid]}
           for k in out.get("key_points", []) if k.get("text")]
    kps = [k for k in kps if k["finding_ids"]]
    if not out.get("summary") or not kps:
        return None
    ans = {"summary": out["summary"], "key_points": kps, "advice": out.get("advice", [])[:4]}
    return {"user": user, "assistant": json.dumps(ans, ensure_ascii=False, separators=(",", ":"))}


def main():
    reps = [Report.model_validate_json(l) for l in (ROOT / "data/distill/url_reports.jsonl").read_text().splitlines() if l.strip()]
    jobs = []
    for r in reps:
        for subj, fj in variants(r, 6):
            jobs.append((subj, fj, r.risk_level.value))
    print(f"{len(jobs)} explanation jobs", flush=True)
    out = ROOT / "data/distill/explain.jsonl"
    kept = 0
    with ThreadPoolExecutor(8) as ex, out.open("w") as f:
        for res in ex.map(lambda j: gen(*j), jobs):
            if res:
                kept += 1
                f.write(json.dumps(res, ensure_ascii=False) + "\n")
    print(f"kept {kept}/{len(jobs)}")


if __name__ == "__main__":
    main()
