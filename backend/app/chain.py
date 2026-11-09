"""On-chain anchoring of report hashes (ThreatRegistry, see contracts/).

Only hashes leave this process: `report_hash` (sha256 of the canonical report) and `indicator_hash` (keccak256 of the
normalised domain). A record proves a report's integrity and history, not that its conclusions are true.

Configured through CHAIN_RPC_URL, CHAIN_CONTRACT_ADDRESS, CHAIN_PRIVATE_KEY and CHAIN_DEPLOY_BLOCK.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from web3 import Web3
from web3.exceptions import Web3Exception, Web3RPCError

from . import store
from .schemas import Report

log = logging.getLogger(__name__)

ABI_PATH = Path(__file__).resolve().parent / "data" / "ThreatRegistry.abi.json"
ZERO_HASH = "0x" + "00" * 32
EXPLORERS = {11155111: "https://sepolia.etherscan.io"}
RECEIPT_TIMEOUT_S = 120
LOCAL_CHAIN_ID = 31337
PUBLIC_TEST_ADDRESS = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"      # Hardhat account #0: its key is published
ANCHOR_WINDOW_S = 3600
_recent_anchors: deque[float] = deque()

# Serialises check-then-send so concurrent requests cannot anchor a report twice or reuse a nonce.
_send_lock = threading.Lock()


class ChainError(Exception):
    """The chain could not answer. Says nothing about whether a report is intact."""


class ChainNotConfigured(ChainError):
    pass


class ChainRateLimited(ChainError):
    pass


def _translating_errors(fn):
    """Convert web3/transport failures to ChainError. Transport messages can embed the RPC URL (and its API key), so
    only RPC-level errors keep their text."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Web3RPCError as e:
            log.warning("chain RPC error: %s", e)
            raise ChainError(f"The chain rejected the request: {e}") from None
        except (Web3Exception, OSError, ValueError) as e:
            log.warning("chain request failed: %r", e)
            raise ChainError(f"Chain request failed ({type(e).__name__})") from None
    return wrapper


def _connect():
    rpc, address = os.getenv("CHAIN_RPC_URL"), os.getenv("CHAIN_CONTRACT_ADDRESS")
    if not (rpc and address):
        raise ChainNotConfigured("Blockchain is not configured (set CHAIN_RPC_URL and CHAIN_CONTRACT_ADDRESS)")
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
    abi = json.loads(ABI_PATH.read_text())
    return w3, w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)


def _signer(w3):
    key = os.getenv("CHAIN_PRIVATE_KEY")
    if not key:
        raise ChainNotConfigured("Blockchain signer is not configured (set CHAIN_PRIVATE_KEY)")
    return w3.eth.account.from_key(key)


def _trusted_reporter(w3) -> str:
    """The only address whose records count. Anyone can write to the registry, so a matching hash alone proves nothing."""
    configured = os.getenv("CHAIN_TRUSTED_REPORTER", "").strip()
    return (configured or _signer(w3).address).lower()


def _spend_anchor_budget() -> None:
    """Every anchor costs gas, so cap them across all callers. Caller holds _send_lock."""
    limit = int(os.getenv("ANCHOR_MAX_PER_HOUR", "60"))
    now = time.monotonic()
    while _recent_anchors and now - _recent_anchors[0] > ANCHOR_WINDOW_S:
        _recent_anchors.popleft()
    if len(_recent_anchors) >= limit:
        raise ChainRateLimited("Too many on-chain registrations right now. Try again later.")
    _recent_anchors.append(now)


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _bytes32(value: str) -> bytes:
    return Web3.to_bytes(hexstr=value)


def _explorer_tx(chain_id: int, tx_hash: str) -> str | None:
    base = EXPLORERS.get(chain_id)
    return f"{base}/tx/{tx_hash}" if base else None


def normalise_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def indicator_hash(domain: str) -> str:
    return _hex(Web3.keccak(text=normalise_domain(domain)))


def report_domain(report: Report) -> str | None:
    if report.target and report.target.registered_domain:
        return report.target.registered_domain
    if report.email and report.email.from_domain:
        return report.email.from_domain
    if report.indicators and report.indicators.domains:
        return report.indicators.domains[0]
    return None


def _submit(w3, contract, account, report_hash: str, indicator: str) -> tuple[int, str, int]:
    """Send the commitment and wait for it to be mined. Returns (registry_id, tx_hash, block_number)."""
    tx = contract.functions.submit(_bytes32(report_hash), _bytes32(indicator)).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT_S)
    if receipt["status"] != 1:
        raise ChainError(f"Transaction {_hex(tx_hash)} reverted")
    event = contract.events.ReportSubmitted().process_receipt(receipt)[0]
    return int(event["args"]["id"]), _hex(tx_hash), int(receipt["blockNumber"])


def _is_on_chain(contract, anchor: dict) -> bool:
    """False when a local dev chain was reset after this anchor was recorded."""
    registry_id = anchor["registry_id"]
    if contract.functions.count().call() <= registry_id:
        return False
    return _hex(contract.functions.reports(registry_id).call()[2]) == anchor["report_hash"]


@_translating_errors
def anchor(report: Report) -> dict:
    """Commit a report's hash on-chain. Idempotent: a report already on this registry is returned as is."""
    w3, contract = _connect()
    account = _signer(w3)
    chain_id = w3.eth.chain_id
    if chain_id != LOCAL_CHAIN_ID and account.address.lower() == PUBLIC_TEST_ADDRESS:
        raise ChainNotConfigured("CHAIN_PRIVATE_KEY is Hardhat's public test key. Use a dedicated wallet on this network.")
    with _send_lock:
        existing = store.get_anchor(report.report_id, chain_id, contract.address)
        if existing and _is_on_chain(contract, existing):
            return {**existing, "explorer_url": _explorer_tx(chain_id, existing["tx_hash"]), "already_anchored": True}

        _spend_anchor_budget()
        domain = report_domain(report)
        indicator = indicator_hash(domain) if domain else ZERO_HASH
        registry_id, tx_hash, block = _submit(w3, contract, account, report.report_hash, indicator)
        record = {
            "report_id": report.report_id, "chain_id": chain_id, "contract_address": contract.address,
            "registry_id": registry_id, "tx_hash": tx_hash, "block_number": block,
            "report_hash": report.report_hash, "indicator_hash": indicator, "reporter": account.address,
            "anchored_at": datetime.now(timezone.utc).isoformat(),
        }
        store.save_anchor(record)
    return {**record, "explorer_url": _explorer_tx(chain_id, tx_hash), "already_anchored": False}


@_translating_errors
def verify(report: Report) -> dict:
    """Recompute the report's hash and compare it with the on-chain value, ignoring the hash stored beside the report
    (anyone able to edit the row could rewrite that too)."""
    w3, contract = _connect()
    chain_id = w3.eth.chain_id
    recomputed = store.compute_hash(report)
    result = {"report_id": report.report_id, "recomputed_hash": recomputed, "chain_id": chain_id,
              "contract_address": contract.address}
    record = store.get_anchor(report.report_id, chain_id, contract.address)
    if not record:
        return {**result, "anchored": False}
    if not _is_on_chain(contract, record):
        return {**result, "anchored": False,
                "detail": "This chain no longer holds the recorded anchor (a local chain was probably reset)."}

    registry_id = record["registry_id"]
    reporter, timestamp, onchain_hash, onchain_indicator = contract.functions.reports(registry_id).call()
    authentic = reporter.lower() == _trusted_reporter(w3)
    if not authentic:
        result["detail"] = "The on-chain record was not written by this service, so it cannot vouch for this report."
    return {
        **result, "anchored": True,
        "integrity_ok": authentic and bool(contract.functions.verify(registry_id, _bytes32(recomputed)).call()),
        "onchain_hash": _hex(onchain_hash), "indicator_hash": _hex(onchain_indicator),
        "registry_id": registry_id, "reporter": reporter,
        "onchain_timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "tx_hash": record["tx_hash"], "block_number": record["block_number"],
        "explorer_url": _explorer_tx(chain_id, record["tx_hash"]),
    }


@_translating_errors
def lookup(domain: str) -> dict:
    """Every on-chain report for a domain written by this service, found by hash from the registry's indexed event."""
    w3, contract = _connect()
    wanted = indicator_hash(domain)
    trusted = _trusted_reporter(w3)
    logs = contract.events.ReportSubmitted().get_logs(
        from_block=int(os.getenv("CHAIN_DEPLOY_BLOCK", "0")),
        to_block="latest",
        argument_filters={"indicatorHash": _bytes32(wanted)},
    )
    logs = [e for e in logs if e["args"]["reporter"].lower() == trusted]
    return {"indicator_hash": wanted, "count": len(logs), "reports": [{
        "registry_id": int(e["args"]["id"]), "report_hash": _hex(e["args"]["reportHash"]),
        "reporter": e["args"]["reporter"], "tx_hash": _hex(e["transactionHash"]),
    } for e in logs]}


def status() -> dict:
    """Connection summary for the UI. Never includes the RPC URL (it may embed an API key) or the signing key."""
    try:
        return _status()
    except ChainNotConfigured as e:
        return {"enabled": False, "connected": False, "detail": str(e)}
    except ChainError as e:
        return {"enabled": True, "connected": False, "detail": str(e)}


@_translating_errors
def _status() -> dict:
    w3, contract = _connect()
    chain_id = w3.eth.chain_id
    signer = _signer(w3).address if os.getenv("CHAIN_PRIVATE_KEY") else None
    return {
        "enabled": True, "connected": True, "chain_id": chain_id, "contract_address": contract.address,
        "total_reports": contract.functions.count().call(), "signer": signer,
        "signer_balance_eth": float(Web3.from_wei(w3.eth.get_balance(signer), "ether")) if signer else None,
        "explorer": EXPLORERS.get(chain_id),
    }
