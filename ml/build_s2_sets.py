"""Assemble System-2 fine-tuning sets (mlx_lm chat format) from teacher labels + explanation data.

Honest evaluation: whole seed families are held out for the test set (their variants never seen in training).
Output: data/s2/{train,valid,test}.jsonl and data/s2/test_gt.jsonl (ground truth for evaluation).
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
sys.path.insert(0, str(ROOT))
from app.ml.s2_prompt import EXPLAIN_SYSTEM, MSG_SYSTEM, msg_user  # noqa: E402
from seeds import SEEDS  # noqa: E402

random.seed(21)
OUT = ROOT / "data" / "s2"
OUT.mkdir(parents=True, exist_ok=True)
KEYS = ["verdict", "scam_type", "impersonated_entity", "tactics", "evidence", "requested_action", "explanation"]
MAXC = 1400


def sid(t: str) -> str:
    return hashlib.sha1(t.encode()).hexdigest()[:16]


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def main():
    seed_of = {sid(s[2]): i for i, s in enumerate(SEEDS)}
    variant_seed = {}
    for l in (ROOT / "data/distill/variants.jsonl").read_text().splitlines():
        d = json.loads(l)
        variant_seed[sid(d["text"])] = seed_of.get(d["seed_id"], -1)
    for t_id, i in seed_of.items():
        variant_seed[t_id] = i

    # Hold out ~20% of seed families, stratified so the test has scams, suspicious and legit hard negatives.
    fams = {"scam": [], "suspicious": [], "legitimate": []}
    for i, (v, _, _) in enumerate(SEEDS):
        fams[v].append(i)
    hold = set()
    for v, ids in fams.items():
        random.shuffle(ids)
        hold |= set(ids[: max(2, len(ids) // 5)])

    rows = []
    for l in (ROOT / "data/distill/labeled.jsonl").read_text().splitlines():
        try:
            rows.append(json.loads(l))
        except json.JSONDecodeError:
            pass                                    # line still being written
    train, valid, test, gt = [], [], [], []
    for r in rows:
        text = r["text"][:MAXC]
        lab = r["label"]
        lab["evidence"] = [e for e in lab.get("evidence", []) if norm(e["quote"]) in norm(text)][:6]
        ans = json.dumps({k: lab.get(k) for k in KEYS}, ensure_ascii=False, separators=(",", ":"))
        ex = {"messages": [{"role": "system", "content": MSG_SYSTEM}, {"role": "user", "content": msg_user(text)},
                           {"role": "assistant", "content": ans}]}
        fam = variant_seed.get(r["id"])
        if fam is not None and fam in hold:
            test.append(ex)
            gt.append({"text": text, "source": r["source"], "gt_verdict": SEEDS[fam][0], "teacher": lab})
        elif fam is None and random.random() < 0.08:
            test.append(ex)
            src_gt = {"sms_ham": "legitimate", "email_safe": "legitimate", "sms_spam": "spam", "email_phish": "scam"}
            gt.append({"text": text, "source": r["source"], "gt_verdict": src_gt.get(r["source"]), "teacher": lab})
        elif random.random() < 0.05:
            valid.append(ex)
        else:
            train.append(ex)

    exp_path = ROOT / "data/distill/explain.jsonl"
    n_exp = 0
    if exp_path.exists():
        for l in exp_path.read_text().splitlines():
            try:
                d = json.loads(l)
            except json.JSONDecodeError:
                continue
            ex = {"messages": [{"role": "system", "content": EXPLAIN_SYSTEM}, {"role": "user", "content": d["user"]},
                               {"role": "assistant", "content": d["assistant"]}]}
            (valid if random.random() < 0.06 else train).append(ex)
            n_exp += 1
    random.shuffle(train)
    for name, data in (("train", train), ("valid", valid), ("test", test)):
        with (OUT / f"{name}.jsonl").open("w") as f:
            for ex in data:
                f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    with (OUT / "test_gt.jsonl").open("w") as f:
        for g in gt:
            f.write(json.dumps(g, ensure_ascii=False) + "\n")
    print(f"train {len(train)} valid {len(valid)} test {len(test)} (explain examples {n_exp}); held-out seed families "
          f"{sorted(hold)}")


if __name__ == "__main__":
    main()
