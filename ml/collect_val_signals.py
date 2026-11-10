"""Collect deployed-pipeline signals (rules, System-1, validated System-2) on the VALIDATION messages,
for tuning the risk engine without touching the test set. Output: data/s2/val_signals.jsonl"""
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app.checks.message import detect_tactics
from app.ml import system1, system2
from app.ml.s2_prompt import MSG_SYSTEM

rows = [json.loads(l) for l in (ROOT / "data/s2/valid.jsonl").read_text().splitlines()]
rows = [r for r in rows if r["messages"][0]["content"] == MSG_SYSTEM]

def one(r):
    text = re.sub(r"^<message>\n|\n</message>$", "", r["messages"][1]["content"])
    gt = json.loads(r["messages"][2]["content"])["verdict"]
    s2, used, ms = system2.analyze_message(text)
    return {"text": text, "gt": gt, "rules": detect_tactics(text), "s1_p": system1.msg_score(text).probability,
            "s2": s2, "s2_model": used}

with ThreadPoolExecutor(4) as ex:
    out = list(ex.map(one, rows))
(ROOT / "data/s2/val_signals.jsonl").write_text("".join(json.dumps(o, ensure_ascii=False) + "\n" for o in out))
from collections import Counter

print(len(out), "validation messages;", Counter(o["gt"] for o in out), Counter(o["s2_model"][:3] for o in out))
