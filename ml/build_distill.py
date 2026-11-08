"""Build the distillation dataset: augment seeds, then label everything with the local teacher.

Resumable: re-running skips messages already labeled.
Usage: python build_distill.py [--emails N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import teacher
from seeds import SEEDS

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "distill"
OUT.mkdir(parents=True, exist_ok=True)
VARIANTS = OUT / "variants.jsonl"
LABELED = OUT / "labeled.jsonl"
random.seed(7)


def mid(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def phase_augment() -> list[dict]:
    done = load_jsonl(VARIANTS)
    done_seeds = {d["seed_id"] for d in done}
    todo = [(i, s) for i, s in enumerate(SEEDS) if mid(s[2]) not in done_seeds]
    print(f"[augment] {len(todo)} seeds to expand", flush=True)
    with ThreadPoolExecutor(4) as ex, VARIANTS.open("a") as f:
        futs = {ex.submit(teacher.augment, s[2], s[0], s[1]): s for _, s in todo}
        for fut in as_completed(futs):
            verdict, stype, text = futs[fut]
            for v in fut.result():
                rec = {"seed_id": mid(text), "verdict": verdict, "scam_type": stype, "text": v}
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                done.append(rec)
            f.flush()
    return done


def collect(n_emails: int) -> list[dict]:
    items: list[dict] = []
    for verdict, stype, text in SEEDS:
        items.append({"source": "seed", "text": text, "gt_verdict": verdict, "gt_type": stype})
    for v in load_jsonl(VARIANTS):
        items.append({"source": "variant", "text": v["text"], "gt_verdict": v["verdict"], "gt_type": v["scam_type"]})

    sms = ROOT / "data" / "sms" / "SMSSpamCollection"
    rows = [l.split("\t", 1) for l in sms.read_text(encoding="latin-1").splitlines() if "\t" in l]
    spam = [t for g, t in rows if g == "spam"]
    ham = [t for g, t in rows if g == "ham" and len(t) > 25]
    random.shuffle(ham)
    items += [{"source": "sms_spam", "text": t, "gt_verdict": "spam", "gt_type": None} for t in spam]
    items += [{"source": "sms_ham", "text": t, "gt_verdict": "legitimate", "gt_type": None} for t in ham[:1000]]

    emails = ROOT / "data" / "emails" / "Phishing_Email.csv"
    if n_emails and emails.exists():
        import pandas as pd
        try:
            df = pd.read_csv(emails).dropna()
            df = df[df["Email Text"].str.len().between(80, 1500)]
            ph = df[df["Email Type"].str.contains("Phishing")].sample(n_emails // 2, random_state=1)
            ok = df[df["Email Type"].str.contains("Safe")].sample(n_emails // 2, random_state=1)
            items += [{"source": "email_phish", "text": t, "gt_verdict": "phish", "gt_type": None} for t in ph["Email Text"]]
            items += [{"source": "email_safe", "text": t, "gt_verdict": "legitimate", "gt_type": None} for t in ok["Email Text"]]
        except Exception as e:  # partial download etc.
            print(f"[collect] skipping emails: {e}", flush=True)
    return items


def reconcile(item: dict, lab: dict) -> dict | None:
    gt = item["gt_verdict"]
    if item["source"] in ("seed", "variant"):
        lab["verdict"] = gt
        lab["scam_type"] = item["gt_type"]
        if gt == "legitimate":
            lab.update(scam_type="none", tactics=[], evidence=[], impersonated_entity="")
        return lab
    if gt == "legitimate":
        return lab if lab["verdict"] == "legitimate" else None     # drop teacher/ground-truth disagreements
    if gt in ("spam", "phish"):
        if lab["verdict"] == "legitimate":
            if gt == "phish":
                return None
            lab.update(verdict="suspicious", scam_type="marketing_spam")
        return lab
    return lab


def phase_label(items: list[dict]) -> None:
    done = {d["id"] for d in load_jsonl(LABELED)}
    todo = [it for it in items if mid(it["text"]) not in done]
    print(f"[label] {len(todo)} to label ({len(done)} already done)", flush=True)
    kept = dropped = 0
    with ThreadPoolExecutor(int(__import__("os").getenv("THREADS", "8"))) as ex, LABELED.open("a") as f:
        futs = {ex.submit(teacher.label, it["text"]): it for it in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            it = futs[fut]
            try:
                lab = fut.result()
            except Exception as e:
                print(f"[label] error: {e}", flush=True)
                continue
            lab = reconcile(it, lab) if lab else None
            if lab is None:
                dropped += 1
            else:
                kept += 1
                f.write(json.dumps({"id": mid(it["text"]), "source": it["source"], "text": it["text"],
                                    "label": lab}, ensure_ascii=False) + "\n")
            if i % 100 == 0:
                f.flush()
                print(f"[label] {i}/{len(todo)} kept={kept} dropped={dropped}", flush=True)
    print(f"[label] done kept={kept} dropped={dropped}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--emails", type=int, default=0)
    ap.add_argument("--skip-augment", action="store_true")
    a = ap.parse_args()
    if not a.skip_augment:
        phase_augment()
    phase_label(collect(a.emails))
    sys.exit(0)
