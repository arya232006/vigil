"""System-2 client: the self-hosted fine-tuned student model (served by mlx_lm.server or llama.cpp, both
OpenAI-compatible), with the local teacher (Ollama) as fallback. No third-party AI service is ever called.

All outputs are validated: evidence quotes must occur verbatim in the input, explanation points must cite
existing finding ids, and the model can never change the risk level decided by the rule engine.
"""
from __future__ import annotations

import json
import os
import re
import time

import httpx

from .s2_prompt import EXPLAIN_SYSTEM, MSG_SYSTEM, msg_user

S2_URL = os.getenv("S2_BASE_URL", "http://127.0.0.1:8090/v1")          # fine-tuned student (mlx_lm.server)
S2_MODEL = os.getenv("S2_MODEL", "default_model")                       # mlx_lm.server: CLI-loaded model+adapter
S2_NAME = os.getenv("S2_NAME", "vigil-s2-qwen3-1.7b-lora")         # label shown in reports
FALLBACK_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")       # local teacher
FALLBACK_MODEL = os.getenv("FALLBACK_MODEL", "qwen3:4b-instruct-2507-q4_K_M")
TIMEOUT = float(os.getenv("S2_TIMEOUT", "45"))

VERDICTS = {"scam", "suspicious", "legitimate"}

# Deterministic consistency check for AI-claimed harmful tactics: the quote must contain matching vocabulary,
# and negated phrasing ("do not share your OTP") is a warning, not a request.
TACTIC_VOCAB = {
    "otp_request": r"\b(otp|code|pin|one[- ]time|verification)\b",
    "credential_request": r"\b(password|passcode|pin|cvv|card|login|net ?banking|credential|seed|private key|mpin)\b",
    "payment_request": r"(\bpay|\brs\.?|₹|\binr\b|\bfee|\bamount|\btransfer|\bdeposit|\bupi\b|\$|usdt|\bbtc\b|\brecharge)",
    "upfront_fee": r"\b(fee|charge|deposit|pay)",
    "remote_access": r"\b(anydesk|teamviewer|quick ?support|rustdesk|remote|screen ?share|install)",
    "personal_info_request": r"\b(aadhaar|pan|kyc|bank details|account number|date of birth|ifsc|details|address)\b",
}
NEGATED = re.compile(r"\b(do not|don't|dont|never|not to)\b[^.]{0,20}\b(share|send|tell|give|disclose|reveal)\b", re.I)


REQUEST_VERB = re.compile(r"\b(share|send|enter|provide|give|tell|update|confirm|verify|submit|reply|forward|fill|"
                          r"type|complete|upload|click|call|whatsapp|login|log in|sign in)\b", re.I)
NEEDS_VERB = {"otp_request", "credential_request", "personal_info_request"}


def _consistent(tactic: str, quote: str) -> bool:
    rx = TACTIC_VOCAB.get(tactic)
    if rx is None:
        return True
    if tactic in NEEDS_VERB:
        verbs = [m.group(0).lower() for m in REQUEST_VERB.finditer(quote)]
        if not [v for v in verbs if v not in ("login", "log in", "sign in")]:   # 'login' as a noun isn't a request
            return False
    return bool(re.search(rx, quote, re.I)) and not NEGATED.search(quote)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _json(text: str) -> dict | None:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


_LAST_PROBS: dict = {}


def _verdict_probs(logprobs: dict | None) -> dict | None:
    """P(scam / suspicious / legitimate) at the token that starts the verdict value (after `"verdict":"`).
    A bare 's' token is a prefix of both 'scam' and 'suspicious': when it is the chosen token we split its
    mass using the next token's distribution ('c'->scam, 'u'->suspicious)."""
    import math
    if not logprobs:
        return None
    toks = logprobs.get("content") or []
    text = ""

    def classify(tok: str) -> str | None:
        t = tok.strip().lower()
        if not t or t == "s":
            return None
        for v in ("scam", "suspicious", "legitimate"):
            if v.startswith(t) or t.startswith(v):
                return v
        return None

    for i, t in enumerate(toks):
        text += t.get("token", "")
        if not text.replace(" ", "").endswith('"verdict":"'):
            continue
        if i + 1 >= len(toks):
            return None
        mass = {"scam": 0.0, "suspicious": 0.0, "legitimate": 0.0}
        s_mass = 0.0
        for alt in toks[i + 1].get("top_logprobs", []):
            p = math.exp(alt.get("logprob", -99))
            if alt.get("token", "").strip().lower() == "s":
                s_mass += p
            elif (v := classify(alt.get("token", ""))):
                mass[v] += p
        if s_mass and toks[i + 1].get("token", "").strip().lower() == "s" and i + 2 < len(toks):
            nxt = {"scam": 0.0, "suspicious": 0.0}
            for alt in toks[i + 2].get("top_logprobs", []):
                b = alt.get("token", "").strip().lower()
                if b.startswith("c") or b.startswith("ca"):
                    nxt["scam"] += math.exp(alt.get("logprob", -99))
                elif b.startswith("u"):
                    nxt["suspicious"] += math.exp(alt.get("logprob", -99))
            z2 = sum(nxt.values())
            if z2 > 0:
                mass["scam"] += s_mass * nxt["scam"] / z2
                mass["suspicious"] += s_mass * nxt["suspicious"] / z2
        z = sum(mass.values())
        return {k: round(v / z, 5) for k, v in mass.items()} if z > 0 else None
    return None


def _student(system: str, user: str, max_tokens: int, want_probs: bool = False) -> str | None:
    try:
        body = {"model": S2_MODEL, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.0, "max_tokens": max_tokens,
                "chat_template_kwargs": {"enable_thinking": False}}      # must match the fine-tuning format
        if want_probs:
            body.update(logprobs=True, top_logprobs=10)
        r = httpx.post(f"{S2_URL}/chat/completions", timeout=TIMEOUT, json=body)
        r.raise_for_status()
        ch = r.json()["choices"][0]
        if want_probs:
            _LAST_PROBS["v"] = _verdict_probs(ch.get("logprobs"))
        return ch["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError):
        return None


def _teacher(system: str, user: str, max_tokens: int, schema: dict | str | None = None) -> str | None:
    body = {"model": FALLBACK_MODEL, "stream": False, "messages": [{"role": "system", "content": system},
            {"role": "user", "content": user}], "options": {"temperature": 0.0, "num_predict": max_tokens}}
    if schema:
        body["format"] = schema
    try:
        r = httpx.post(f"{FALLBACK_URL}/api/chat", json=body, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError):
        return None


HARMFUL = {"otp_request", "credential_request", "payment_request", "upfront_fee", "remote_access",
           "personal_info_request"}


def _normalize(out: dict | None) -> dict | None:
    """Repair common shape drift from the fallback model (quotes nested in tactics, missing verdict)."""
    if not isinstance(out, dict):
        return None
    tactics, evidence = [], list(out.get("evidence") or [])
    for t in out.get("tactics") or []:
        if isinstance(t, dict):
            if t.get("tactic"):
                tactics.append(t["tactic"])
            if t.get("quote"):
                evidence.append({"tactic": t.get("tactic"), "quote": t["quote"]})
        elif isinstance(t, str):
            tactics.append(t)
    out["tactics"], out["evidence"] = tactics, [e for e in evidence if isinstance(e, dict)]
    if out.get("verdict") not in VERDICTS:
        out["verdict"] = ("scam" if set(tactics) & HARMFUL else "suspicious" if tactics else "legitimate")
        out["verdict_inferred"] = True
    return out


_CAL_PATH = __import__("pathlib").Path(__file__).resolve().parent / "artifacts" / "s2_calibration.json"


ROUTER_ENABLED = os.getenv("ROUTER_ENABLED", "1") != "0"


def router_threshold() -> float | None:
    try:
        return json.loads(_CAL_PATH.read_text()).get("router_s1_threshold")
    except (OSError, ValueError):
        return None


def calibrate(p_raw: float) -> float | None:
    """Platt scaling fitted on the validation set (ml/calibrate_s2.py). Returns None if not fitted yet."""
    import math
    try:
        c = json.loads(_CAL_PATH.read_text())
    except (OSError, ValueError):
        return None
    x = math.log(max(p_raw, 1e-6) / max(1 - p_raw, 1e-6))
    return round(1 / (1 + math.exp(-(c["a"] * x + c["b"]))), 4)


def status() -> dict:
    out = {"student_url": S2_URL, "student_model": S2_NAME, "fallback_model": FALLBACK_MODEL}
    try:
        out["student_up"] = httpx.get(f"{S2_URL}/models", timeout=2).status_code == 200
    except httpx.HTTPError:
        out["student_up"] = False
    try:
        out["fallback_up"] = httpx.get(f"{FALLBACK_URL}/api/version", timeout=2).status_code == 200
    except httpx.HTTPError:
        out["fallback_up"] = False
    return out


def analyze_message(text: str) -> tuple[dict | None, str, int]:
    """Returns (validated_result, model_used, latency_ms)."""
    t0 = time.monotonic()
    _LAST_PROBS.pop("v", None)
    raw, used = _student(MSG_SYSTEM, msg_user(text), 400, want_probs=True), f"s2:{S2_NAME}"
    out = _json(raw) if raw else None
    probs = _LAST_PROBS.get("v") if out else None
    if not out or out.get("verdict") not in VERDICTS:
        from ..ml.teacher_schema import LABEL_SCHEMA, LABEL_SYSTEM  # lazy: only for the fallback path
        # generic JSON mode: schema-constrained decoding suppresses the nested evidence quotes
        skeleton = ('\nReturn exactly this JSON shape: {"verdict": "scam|suspicious|legitimate", "scam_type": "...", '
                    '"impersonated_entity": "...", "tactics": ["..."], "evidence": [{"tactic": "...", "quote": "..."}], '
                    '"requested_action": "...", "explanation": "..."}')
        raw, used = _teacher(LABEL_SYSTEM + skeleton, msg_user(text), 600, "json"), f"fallback:{FALLBACK_MODEL}"
        out = _normalize(_json(raw)) if raw else None
    if not out or out.get("verdict") not in VERDICTS:
        return None, used, int((time.monotonic() - t0) * 1000)
    nt = _norm(text)
    def specific(q: str) -> bool:      # a quote of (almost) the whole message is not evidence of anything
        return len(q) <= 200 and not (len(nt) > 80 and len(_norm(q)) > 0.7 * len(nt))
    ev = [e for e in out.get("evidence", []) if isinstance(e, dict) and e.get("quote")
          and _norm(e["quote"]) in nt and specific(e["quote"]) and _consistent(e.get("tactic", ""), e["quote"])]
    out["ungrounded_evidence_dropped"] = len(out.get("evidence", [])) - len(ev)
    out["evidence"] = ev
    if used.startswith("s2:") and probs:
        out["verdict_probs"] = probs
        out["p_unsafe_raw"] = round(probs["scam"] + probs["suspicious"], 5)
        out["p_unsafe"] = calibrate(out["p_unsafe_raw"])
    grounded_tactics = {e.get("tactic") for e in ev}
    out["tactics"] = sorted({t for t in out.get("tactics", []) if isinstance(t, str)})
    out["ungrounded_tactics"] = sorted(set(out["tactics"]) - grounded_tactics)
    return out, used, int((time.monotonic() - t0) * 1000)


def explain(risk_level: str, findings: list[dict], subject: str) -> tuple[dict | None, str]:
    payload = json.dumps({"subject": subject[:300], "risk_level": risk_level, "findings": findings}, ensure_ascii=False)
    user = f"<findings>\n{payload[:7000]}\n</findings>"
    raw, used = _student(EXPLAIN_SYSTEM, user, 450), f"s2:{S2_NAME}"
    out = _json(raw) if raw else None
    if not out or "summary" not in out:
        raw, used = _teacher(EXPLAIN_SYSTEM, user, 600, EXPLAIN_SCHEMA), f"fallback:{FALLBACK_MODEL}"
        out = _json(raw) if raw else None
    if not out or "summary" not in out:
        return None, used
    valid = {f["id"] for f in findings}
    kps = []
    for kp in out.get("key_points", []):
        if isinstance(kp, dict) and kp.get("text"):
            ids = [i for i in kp.get("finding_ids", []) if i in valid]
            if ids:                                   # grounding: drop points that cite nothing real
                kps.append({"text": kp["text"], "finding_ids": ids})
    out["key_points"] = kps
    out["advice"] = [a for a in out.get("advice", []) if isinstance(a, str)][:5]
    return out, used


EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "key_points": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "finding_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["text", "finding_ids"]}},
        "advice": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "key_points", "advice"],
}
