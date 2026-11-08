"""Web3 layer against an in-memory stand-in for ThreatRegistry (the contract has its own Hardhat tests)."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import chain, store
from app.main import app
from app.schemas import Explanation, Report, RiskLevel, TargetInfo

ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
SIGNER = SimpleNamespace(address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


def _call(value):
    return SimpleNamespace(call=lambda: value)


class FakeRegistry:
    address = ADDRESS

    def __init__(self):
        self.records = []
        self.functions = SimpleNamespace(
            count=lambda: _call(len(self.records)),
            reports=lambda i: _call(self.records[i]),
            verify=lambda i, h: _call(self.records[i][2] == h),
        )


@pytest.fixture
def registry(monkeypatch):
    fake = FakeRegistry()
    w3 = SimpleNamespace(eth=SimpleNamespace(chain_id=31337))

    def submit(_w3, _contract, account, report_hash, indicator):
        fake.records.append((account.address, 1_700_000_000, bytes.fromhex(report_hash[2:]),
                             bytes.fromhex(indicator[2:])))
        return len(fake.records) - 1, "0x" + "ab" * 32, 7

    monkeypatch.setattr(chain, "_connect", lambda: (w3, fake))
    monkeypatch.setattr(chain, "_signer", lambda _w3: SIGNER)
    monkeypatch.setattr(chain, "_submit", submit)
    return fake


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def report():
    r = Report(report_id=uuid.uuid4().hex[:12], input_type="domain", input="evil.example",
               analyzed_at="2026-11-08T10:00:00+00:00", risk_level=RiskLevel.HIGH, risk_score=80, confidence=0.9,
               target=TargetInfo(submitted="evil.example", registered_domain="Evil.Example."),
               explanation=Explanation(summary="s", generated_by="template"))
    r.report_hash = store.compute_hash(r)
    store.save(r, [])
    return r


def _tamper(report, rewrite_stored_hash=True):
    """What an attacker with database access would do: change the verdict and, optionally, fix up the stored hash."""
    edited = report.model_copy(update={"risk_level": RiskLevel.LOW})
    if rewrite_stored_hash:
        edited.report_hash = store.compute_hash(edited)
    store.save(edited, [])


def test_indicator_hash_normalises_the_domain():
    assert chain.indicator_hash(" Evil.Example. ") == chain.indicator_hash("evil.example")


def test_anchor_commits_the_report_and_domain_hashes(client, registry, report):
    body = client.post(f"/api/reports/{report.report_id}/anchor").json()
    assert body["registry_id"] == 0 and body["already_anchored"] is False
    assert "0x" + registry.records[0][2].hex() == report.report_hash
    assert "0x" + registry.records[0][3].hex() == chain.indicator_hash("evil.example")


def test_anchor_is_idempotent(client, registry, report):
    client.post(f"/api/reports/{report.report_id}/anchor")
    again = client.post(f"/api/reports/{report.report_id}/anchor").json()
    assert again["already_anchored"] is True and len(registry.records) == 1


def test_report_without_a_domain_commits_a_zero_indicator(client, registry, report):
    store.save(report.model_copy(update={"target": None, "report_hash": ""}), [])
    r = store.get(report.report_id)
    r.report_hash = store.compute_hash(r)
    store.save(r, [])
    assert client.post(f"/api/reports/{report.report_id}/anchor").json()["indicator_hash"] == chain.ZERO_HASH


def test_verify_passes_for_an_untouched_report(client, registry, report):
    client.post(f"/api/reports/{report.report_id}/anchor")
    body = client.get(f"/api/reports/{report.report_id}/chain-verify").json()
    assert body["anchored"] is True and body["integrity_ok"] is True
    assert body["onchain_hash"] == report.report_hash


def test_chain_catches_a_tamper_that_rewrites_the_stored_hash(client, registry, report):
    client.post(f"/api/reports/{report.report_id}/anchor")
    _tamper(report)
    assert client.get(f"/api/reports/{report.report_id}/verify").json()["integrity_ok"] is True   # local check fooled
    body = client.get(f"/api/reports/{report.report_id}/chain-verify").json()
    assert body["integrity_ok"] is False and body["onchain_hash"] == report.report_hash


def test_unanchored_report_is_not_reported_as_tampered(client, registry, report):
    body = client.get(f"/api/reports/{report.report_id}/chain-verify").json()
    assert body["anchored"] is False and body["integrity_ok"] is None


def test_refuses_to_anchor_a_report_that_fails_its_own_hash(client, registry, report):
    _tamper(report, rewrite_stored_hash=False)
    assert client.post(f"/api/reports/{report.report_id}/anchor").status_code == 409
    assert registry.records == []


def test_reanchors_after_a_dev_chain_reset(client, registry, report):
    client.post(f"/api/reports/{report.report_id}/anchor")
    registry.records.clear()
    assert client.get(f"/api/reports/{report.report_id}/chain-verify").json()["anchored"] is False
    assert client.post(f"/api/reports/{report.report_id}/anchor").json()["already_anchored"] is False
    assert len(registry.records) == 1


def test_unconfigured_chain_returns_503_and_a_disabled_status(client, report, monkeypatch):
    monkeypatch.delenv("CHAIN_RPC_URL", raising=False)
    monkeypatch.delenv("CHAIN_CONTRACT_ADDRESS", raising=False)
    assert client.post(f"/api/reports/{report.report_id}/anchor").status_code == 503
    assert client.get("/api/chain/status").json()["enabled"] is False


def test_chain_outage_is_not_reported_as_tampering(client, report, monkeypatch):
    def down():
        raise chain.ChainError("Chain request failed (ConnectionError)")
    monkeypatch.setattr(chain, "_connect", down)
    assert client.get(f"/api/reports/{report.report_id}/chain-verify").status_code == 502


def test_transport_errors_do_not_leak_the_rpc_url(monkeypatch):
    def leaky():
        raise OSError("cannot reach https://sepolia.example/v3/SECRET-KEY")
    monkeypatch.setattr(chain, "_connect", leaky)
    status = chain.status()
    assert status["connected"] is False and "SECRET-KEY" not in status["detail"]


def test_unknown_report_is_404(client, registry):
    assert client.post("/api/reports/missing/anchor").status_code == 404
