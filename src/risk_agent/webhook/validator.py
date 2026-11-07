"""Webhook request signature and payload validation."""

import hashlib
import hmac
from typing import Dict, Optional, Set, Tuple


def validate_github_signature(
    payload_bytes: bytes,
    signature_header: Optional[str],
    secret: str
) -> bool:
    """Validates GitHub HMAC-SHA256 signature using constant-time comparison.

    Args:
        payload_bytes: Raw HTTP request body bytes.
        signature_header: Header value from X-Hub-Signature-256 (format: sha256=...).
        secret: Webhook shared secret string.

    Returns:
        True if signature matches, False otherwise.
    """
    if not signature_header or not secret:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_sig = signature_header[7:].strip()
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    computed_sig = mac.hexdigest()

    return hmac.compare_digest(computed_sig, expected_sig)


def validate_webhook_headers(
    headers: Dict[str, str],
    allowed_events: Optional[Set[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Validates GitHub event headers.

    Args:
        headers: Case-insensitive or normalized HTTP request headers.
        allowed_events: Set of allowed GitHub event names (defaults to {'pull_request', 'ping'}).

    Returns:
        Tuple of (is_valid, error_message).
    """
    if allowed_events is None:
        allowed_events = {"pull_request", "ping"}

    # Normalize header keys to lowercase
    norm_headers = {k.lower(): v for k, v in headers.items()}

    event_type = norm_headers.get("x-github-event")
    if not event_type:
        return False, "Missing X-GitHub-Event header"

    if event_type not in allowed_events:
        return False, f"Event '{event_type}' is not supported (allowed: {allowed_events})"

    delivery_id = norm_headers.get("x-github-delivery")
    if not delivery_id or not delivery_id.strip():
        return False, "Missing X-GitHub-Delivery header"

    return True, None


def validate_payload_size(
    payload_bytes: bytes,
    max_bytes: int = 10_000_000
) -> Tuple[bool, Optional[str]]:
    """Checks that the payload does not exceed the maximum allowed size."""
    if len(payload_bytes) > max_bytes:
        return False, f"Payload size {len(payload_bytes)} bytes exceeds limit of {max_bytes} bytes"
    return True, None

