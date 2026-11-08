"""Round-2 data: expand SEEDS2 with the local teacher, label, extract verbatim evidence.
Output: data/distill/round2.jsonl (same row format as labeled.jsonl)."""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import teacher  # noqa: E402
from backfill_evidence import extract  # noqa: E402
from build_distill import mid  # noqa: E402
from round2_seeds import FRESH_HOLDOUT, SEEDS2  # noqa: E402

OUT = ROOT / "data/distill/round2.jsonl"
HOLD = {t for _, t in FRESH_HOLDOUT}


def expand(seed):
    verdict, stype, text = seed
    return [(verdict, stype, text, "r2seed")] + [(verdict, stype, v, "r2variant") for v in teacher.augment(text, verdict, stype, n=8)]


def label(item):
    verdict, stype, text, src = item
    if text in HOLD:
        return None
    lab = teacher.label(text)
    if not lab:
        return None
    lab["verdict"], lab["scam_type"] = verdict, stype
    if verdict == "legitimate":
        lab.update(scam_type="none", tactics=[], evidence=[], impersonated_entity="")
    elif lab.get("tactics") and not lab.get("evidence"):
        lab["evidence"] = extract(text, lab["tactics"])
    return {"id": mid(text), "source": src, "text": text, "label": lab}


def main():
    with ThreadPoolExecutor(6) as ex:
        items = [i for group in ex.map(expand, SEEDS2) for i in group]
    print(f"{len(items)} messages after expansion", flush=True)
    with ThreadPoolExecutor(6) as ex:
        rows = [r for r in ex.map(label, items) if r]
    OUT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    from collections import Counter
    print(len(rows), "labeled;", Counter(r["label"]["verdict"] for r in rows),
          "; with evidence:", sum(1 for r in rows if r["label"]["evidence"]))


if __name__ == "__main__":
    main()
