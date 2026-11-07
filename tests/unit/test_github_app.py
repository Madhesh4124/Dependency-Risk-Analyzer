"""Unit tests for Phase 6 GitHub App authentication and token management."""

import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
import httpx
import pytest

from risk_agent.webhook.github_app import GitHubAppAuth, generate_app_jwt


@pytest.fixture
def rsa_key_pem():
    """Generates an ephemeral RSA private key in PEM format for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("utf-8")


def test_generate_app_jwt(rsa_key_pem):
    """Verifies RS256 JWT generation structure and claims."""
    jwt = generate_app_jwt(app_id="123456", private_key_pem=rsa_key_pem, expiration_seconds=500)
    parts = jwt.split(".")
    assert len(parts) == 3

    # Decode header
    header_json = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
    header = json.loads(header_json)
    assert header.get("alg") == "RS256"
    assert header.get("typ") == "JWT"

    # Decode payload
    payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
    payload = json.loads(payload_json)
    assert payload.get("iss") == "123456"
    assert payload.get("exp") - payload.get("iat") == 560  # 500 + 60s buffer


@pytest.mark.anyio
async def test_fallback_to_pat_when_not_configured():
    """Verifies that GitHubAppAuth transparently returns fallback PAT when App not configured."""
    auth = GitHubAppAuth(app_id=None, private_key_pem=None, fallback_token="ghp_test_token")
    assert not auth.is_app_configured

    token = await auth.get_installation_token(installation_id=999)
    assert token == "ghp_test_token"


@pytest.mark.anyio
async def test_get_installation_token_success_and_cache(rsa_key_pem):
    """Verifies token retrieval and in-memory caching."""
    auth = GitHubAppAuth(
        app_id="123456",
        private_key_pem=rsa_key_pem,
        fallback_token="ghp_fallback",
        api_base_url="https://api.github.com",
    )
    assert auth.is_app_configured

    call_count = 0

    def mock_transport(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        assert request.url.path == "/app/installations/42/access_tokens"
        assert request.headers["Authorization"].startswith("Bearer ")
        return httpx.Response(
            201,
            json={
                "token": "ghs_installation_token_abc",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as client:
        # First call: hits API
        token1 = await auth.get_installation_token(installation_id=42, client=client)
        assert token1 == "ghs_installation_token_abc"
        assert call_count == 1

        # Second call: served from in-memory cache
        token2 = await auth.get_installation_token(installation_id=42, client=client)
        assert token2 == "ghs_installation_token_abc"
        assert call_count == 1  # No additional network request


@pytest.mark.anyio
async def test_token_exchange_failure_falls_back_to_pat(rsa_key_pem):
    """Verifies that an API failure during token exchange degrades gracefully to PAT."""
    auth = GitHubAppAuth(
        app_id="123456",
        private_key_pem=rsa_key_pem,
        fallback_token="ghp_safe_fallback",
    )

    def mock_error_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Installation not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_error_transport)) as client:
        token = await auth.get_installation_token(installation_id=999, client=client)
        assert token == "ghp_safe_fallback"
