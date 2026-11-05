"""Unit tests for webhook HMAC validation and delivery deduplication."""

import hashlib
import hmac
import time
import pytest
from risk_agent.webhook.validator import (
    validate_github_signature,
    validate_webhook_headers,
    validate_payload_size,
)
from risk_agent.webhook.deduplication import InMemoryDeliveryStore


def compute_test_signature(payload: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class TestSignatureValidation:
    def test_valid_signature(self):
        secret = "super-secret-token"
        body = b'{"action": "opened", "pull_request": {"id": 123}}'
        sig = compute_test_signature(body, secret)
        assert validate_github_signature(body, sig, secret) is True

    def test_invalid_signature(self):
        secret = "super-secret-token"
        body = b'{"action": "opened"}'
        wrong_sig = "sha256=1111111111111111111111111111111111111111111111111111111111111111"
        assert validate_github_signature(body, wrong_sig, secret) is False

    def test_tampered_payload(self):
        secret = "super-secret-token"
        body = b'{"action": "opened"}'
        sig = compute_test_signature(body, secret)
        tampered_body = b'{"action": "closed"}'
        assert validate_github_signature(tampered_body, sig, secret) is False

    def test_missing_or_malformed_signature(self):
        secret = "super-secret-token"
        body = b'{"action": "opened"}'
        assert validate_github_signature(body, None, secret) is False
        assert validate_github_signature(body, "", secret) is False
        assert validate_github_signature(body, "invalid-format", secret) is False
        assert validate_github_signature(body, "md5=12345", secret) is False


class TestHeaderAndSizeValidation:
    def test_valid_headers(self):
        headers = {
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-uuid-1234",
        }
        valid, err = validate_webhook_headers(headers)
        assert valid is True
        assert err is None

    def test_unsupported_event(self):
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-uuid-1234",
        }
        valid, err = validate_webhook_headers(headers)
        assert valid is False
        assert "not supported" in err

    def test_missing_delivery_header(self):
        headers = {"X-GitHub-Event": "pull_request"}
        valid, err = validate_webhook_headers(headers)
        assert valid is False
        assert "Missing X-GitHub-Delivery" in err

    def test_payload_size_limit(self):
        small_body = b"x" * 100
        ok, err = validate_payload_size(small_body, max_bytes=1000)
        assert ok is True

        large_body = b"x" * 2000
        ok, err = validate_payload_size(large_body, max_bytes=1000)
        assert ok is False
        assert "exceeds limit" in err


class TestDeduplication:
    def test_deduplication_records_and_detects(self):
        store = InMemoryDeliveryStore(default_ttl_seconds=60)
        del_id = "test-delivery-abc-123"

        assert store.is_duplicate(del_id) is False
        assert store.record_delivery(del_id) is True
        assert store.is_duplicate(del_id) is True
        assert store.record_delivery(del_id) is False  # Cannot record duplicate

    def test_deduplication_ttl_expiry(self):
        store = InMemoryDeliveryStore(default_ttl_seconds=1)
        del_id = "short-lived-delivery"

        store.record_delivery(del_id, ttl_seconds=1)
        assert store.is_duplicate(del_id) is True

        time.sleep(1.1)
        assert store.is_duplicate(del_id) is False

