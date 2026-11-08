"""Deterministic message analysis: indicator (IOC) extraction + rule-based tactic detection.
These rules are the evidence layer that cross-checks the AI model."""
from __future__ import annotations

import re

from ..schemas import Indicators

URL_RX = re.compile(
    r"(?i)\b(?:(?:https?|hxxps?)://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+|"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+(?:com|in|net|org|co|io|xyz|top|shop|info|link|ly|me|app|"
    r"site|online|live|click|gov|edu|biz|us|uk|ru|cn|cc|pw|tk|ml|ga|cf|gq|icu|buzz|rest|cfd|sbs|vip|win|support|help|"
    r"store|fun|bank|page|dev|ai|gl|to|sh|gd|at)\b(?:/[^\s<>\"')\]]*)?)")
EMAIL_RX = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
UPI_RX = re.compile(r"(?i)\b[a-z0-9._-]{2,}@(?:ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|upi|apl|ibl|axl|icici|sbi|hdfcbank|axisbank|kotak|yesbank|fbl|idfcbank|jupiteraxis|freecharge|airtel)\b")
PHONE_RX = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|(?<!\d)\+?\d{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}(?!\d)|\b1-?800-?[0-9X]{3}-?[0-9X]{4}\b")

NEG = r"(?<!not )(?<!n't )(?<!never )(?<!dont )"
TACTIC_RULES: dict[str, list[str]] = {
    "otp_request": [rf"{NEG}\b(?:share|send|tell|forward|provide|give|reply with|enter)\b[^.\n]{{0,40}}\b(?:otp|one[- ]time|verification code|6[- ]digit code|code|pin)\b",
                    r"\b(?:otp|code)\b[^.\n]{0,25}\b(?:to (?:me|us|verify|continue)|for verification)\b"],
    "credential_request": [rf"{NEG}\b(?:enter|share|confirm|update|provide|send|verify)\b[^.\n]{{0,40}}\b(?:password|passcode|login details|net ?banking|cvv|card (?:number|details)|upi pin|mpin|atm pin|seed phrase|recovery phrase|private key)\b"],
    "payment_request": [r"\b(?:pay|send|transfer|deposit|recharge)\b[^.\n]{0,40}(?:rs\.?|₹|inr|usd|\$|usdt|btc|fee|charge|amount|upi)",
                        r"\b(?:processing|registration|clearance|customs|security|file|activation|release) (?:fee|charge|deposit)\b"],
    "upfront_fee": [r"\b(?:processing|registration|clearance|customs|security|file|activation|release|refundable) (?:fee|charge|deposit)\b",
                    r"\bpay\b[^.\n]{0,30}\bto (?:claim|receive|release|unlock|get)\b"],
    "remote_access": [r"\b(?:anydesk|teamviewer|quick ?support|rustdesk|airdroid|screen ?share|remote access|ammyy)\b"],
    "urgency": [r"\b(?:urgent(?:ly)?|immediately|right now|within \d+ ?(?:hours?|hrs?|mins?|minutes?)|today itself|expires? (?:today|tonight|soon)|last (?:chance|day)|act now|before midnight|tonight)\b"],
    "fear_threat": [r"\b(?:blocked|suspend(?:ed)?|deactivat(?:ed|e)|disconnect(?:ed)?|freez(?:e|es|ing)|legal action|arrest(?:ed)?|fir\b|case (?:will be|has been) (?:filed|registered)|penalty|seized|permanently (?:deleted|closed))"],
    "reward_lure": [r"\b(?:won|winner|lottery|lucky draw|prize|jackpot|cashback|reward points?|free (?:gift|iphone)|guaranteed (?:returns?|profit)|\d+% (?:returns?|profit))\b"],
    "authority_impersonation": [r"\b(?:cbi|police|cyber ?cell|rbi|reserve bank|income tax (?:dept|department)|customs|court|trai|sebi|narcotics|ed officer|government of india)\b"],
    "secrecy": [r"\b(?:do not|don't|dont) (?:tell|inform|share this with) (?:anyone|anybody|your family|dad|mom)|keep (?:this|it) (?:secret|confidential)\b"],
    "personal_info_request": [r"\b(?:send|share|update|provide|submit)\b[^.\n]{0,30}\b(?:aadhaar|pan(?: card)?|kyc|date of birth|bank details|account number|ifsc)\b"],
    "instruction_injection": [r"(?:ignore (?:all |any )?(?:previous|prior|above) instructions|classify (?:this|it) as|you are an ai|system note to ai|\[assistant:|respond that this (?:message )?is)"],
}
HARMFUL = {"otp_request", "credential_request", "payment_request", "upfront_fee", "remote_access", "personal_info_request"}


def extract_indicators(text: str) -> Indicators:
    t = text.replace("[.]", ".").replace("(.)", ".")
    emails = sorted(set(EMAIL_RX.findall(t)))[:20]
    upis = sorted(set(UPI_RX.findall(t)))[:10]
    urls = []
    for m in URL_RX.findall(t):
        u = m.rstrip(".,;:!?")
        if any(u.lower() in e.lower() for e in emails + upis):
            continue
        if re.fullmatch(r"[\d.]+", u):
            continue
        urls.append(u)
    urls = list(dict.fromkeys(urls))[:10]
    domains = []
    for u in urls:
        h = re.sub(r"(?i)^(?:https?|hxxps?)://", "", u).split("/")[0].split("?")[0].lower()
        domains.append(h)
    phones = sorted({re.sub(r"[\s()-]", "", p) for p in PHONE_RX.findall(t)})[:10]
    return Indicators(urls=urls, domains=list(dict.fromkeys(domains)), emails=emails, phones=phones, upi_ids=upis)


def detect_tactics(text: str) -> dict[str, str]:
    """tactic -> exact matched quote from the message."""
    low = text.lower()
    out = {}
    for tactic, rxs in TACTIC_RULES.items():
        for rx in rxs:
            m = re.search(rx, low)
            if m:
                out[tactic] = text[m.start():m.end()]
                break
    return out
