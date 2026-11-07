"""Unit and integration tests for Phase 5 FastAPI Webhook service (Cloud Run deployment)."""

import hashlib
import hmac
import json
import uuid
import pytest
from fastapi.testclient import TestClient

from risk_agent.secrets import clear_secret_cache
from risk_agent.webhook.app import app


@pytest.fixture(autouse=True)
def reset_test_secrets(monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    clear_secret_cache()
    yield
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
    clear_secret_cache()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check_endpoint(client):
    """Verifies that the /health endpoint reports service health and cloud store status."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "dependency-risk-agent"
    assert data["version"] == "0.1.0"
    assert "gcp_project" in data


def test_webhook_header_validation_errors(client):
    """Verifies that requests missing required GitHub headers are rejected with HTTP 400."""
    # 1. Missing all headers
    resp = client.post("/webhook", content=b"{}")
    assert resp.status_code == 400

    # 2. Unsupported event (push instead of pull_request)
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": str(uuid.uuid4()),
    }
    resp = client.post("/webhook", headers=headers, content=b"{}")
    assert resp.status_code == 400
    assert "not supported" in resp.json()["detail"].lower()


def test_webhook_payload_size_limit(client):
    """Verifies that payloads exceeding maximum size are rejected with HTTP 413."""
    oversized_body = b"x" * (10_000_001)
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": str(uuid.uuid4()),
    }
    resp = client.post("/webhook", headers=headers, content=oversized_body)
    assert resp.status_code == 413
    assert "exceeds limit" in resp.json()["detail"].lower()


def test_webhook_hmac_signature_validation(monkeypatch, client):
    """Verifies constant-time HMAC-SHA256 signature verification."""
    secret = "test-webhook-secret-phase5"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)

    payload = {
        "action": "closed",  # Ignored action so it doesn't run full pipeline
        "pull_request": {"number": 1},
    }
    payload_bytes = json.dumps(payload).encode("utf-8")

    # 1. Invalid signature -> 401
    bad_headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": str(uuid.uuid4()),
        "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
    }
    bad_resp = client.post("/webhook", headers=bad_headers, content=payload_bytes)
    assert bad_resp.status_code == 401
    assert "Invalid or missing X-Hub-Signature-256" in bad_resp.json()["detail"]

    # 2. Valid signature -> 200
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    valid_sig = f"sha256={mac.hexdigest()}"
    good_headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": str(uuid.uuid4()),
        "X-Hub-Signature-256": valid_sig,
    }
    good_resp = client.post("/webhook", headers=good_headers, content=payload_bytes)
    assert good_resp.status_code == 200
    assert good_resp.json()["status"] == "ignored"


def test_webhook_delivery_deduplication(monkeypatch, client):
    """Verifies that deliveries with identical X-GitHub-Delivery are idempotently deduplicated."""
    secret = "test-dedup-secret"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    clear_secret_cache()

    delivery_id = f"test-dedup-{uuid.uuid4()}"
    payload = {
        "action": "closed",
        "pull_request": {"number": 99},
    }
    payload_bytes = json.dumps(payload).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    valid_sig = f"sha256={mac.hexdigest()}"

    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "X-Hub-Signature-256": valid_sig,
    }

    # First delivery: recorded and processed
    resp1 = client.post("/webhook", headers=headers, content=payload_bytes)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "ignored"

    # Second delivery with exact same ID: detected as duplicate
    resp2 = client.post("/webhook", headers=headers, content=payload_bytes)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["status"] == "duplicate"
    assert data2["delivery_id"] == delivery_id


def test_reports_api_not_found(client):
    """Verifies that requesting a nonexistent report ID returns 404."""
    resp = client.get(f"/reports/nonexistent-{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "scenario_name,expected_verdict",
    [
        ("scenario_1", "NO_RISK_FOUND"),
        ("scenario_2", "RISKY"),
        ("scenario_3", "REVIEW"),
        ("scenario_4", "RISKY"),
    ],
)
def test_phase5_demo_scenarios_via_api(client, scenario_name, expected_verdict):
    """Verifies that all 4 Phase 5 verification scenarios evaluate to their required verdicts."""
    resp = client.post(f"/evaluate/demo?scenario_name={scenario_name}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["verdict"] == expected_verdict
    assert data["matches_expected"] is True

    # Check report was archived and can be retrieved via /reports/{id}
    report_id = data["report_id"]
    rep_resp = client.get(f"/reports/{report_id}")
    assert rep_resp.status_code == 200
    archived = rep_resp.json()
    assert archived["verdict"] == expected_verdict
