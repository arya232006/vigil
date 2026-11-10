"""Run the real pipeline on a diverse URL set to collect realistic findings for the explanation task.
Explanations are disabled here (template) so the teacher is not needed. Output: data/distill/url_reports.jsonl"""
from __future__ import annotations

import random
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app import pipeline  # noqa: E402
from app.checks import threatintel  # noqa: E402

pipeline._explain = pipeline._template_explanation          # no LLM during collection
random.seed(11)
OUT = ROOT / "data" / "distill" / "url_reports.jsonl"


def main():
    threatintel.load()
    phish = [l.strip() for l in (ROOT.parent / "backend/app/data/feeds/openphish.txt").read_text().splitlines() if l.strip()]
    tranco = [l.split(",")[1].strip() for l in (ROOT / "data/tranco/top-1m.csv").read_text().splitlines()[:300_000]]
    urls = (random.sample(phish, 28) + random.sample(tranco[:2000], 12) + random.sample(tranco[50_000:300_000], 12) +
            ["https://expired.badssl.com", "https://wrong.host.badssl.com", "https://self-signed.badssl.com",
             "https://untrusted-root.badssl.com", "https://revoked.badssl.com", "http://http.badssl.com",
             "https://mixed-script.badssl.com", "paypa1-account-verify.com", "hdfc-netbanking-secure.top",
             "bit.ly/3xDhLpay"])
    with ThreadPoolExecutor(6) as ex, OUT.open("w") as f:
        for r in ex.map(lambda u: _safe(u), urls):
            if r:
                f.write(r.model_dump_json() + "\n")
                print(r.risk_level.value, r.input[:70], flush=True)


def _safe(u):
    try:
        return pipeline.analyze(u)
    except Exception as e:
        print("ERR", u, e, flush=True)
        return None


if __name__ == "__main__":
    main()
