"""Multi-tenant GitHub App authentication and token management for Phase 6.

Generates RS256 JWTs and mints short-lived installation access tokens per GitHub App specs.
Supports seamless fallback to personal access tokens (PAT) when GitHub App credentials are not set.
"""

import base64
from datetime import datetime, timezone
import json
import logging
import time
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import httpx

from risk_agent.secrets import get_secret

logger = logging.getLogger(__name__)


def generate_app_jwt(app_id: str, private_key_pem: str, expiration_seconds: int = 540) -> str:
    """Generates an RS256 signed JSON Web Token (JWT) for GitHub App authentication."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": now - 60,  # 60s in the past to allow for clock drift
        "exp": now + expiration_seconds,
        "iss": str(app_id),
    }

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Load PEM private key
    # Handles both PKCS#1 and PKCS#8 formats
    key = load_pem_private_key(private_key_pem.strip().encode("utf-8"), password=None)

    # Sign with SHA256 PKCS#1 v1.5
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = b64url(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


class GitHubAppAuth:
    """Manages GitHub App authentication, JWT creation, and installation token lifecycle."""

    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        fallback_token: Optional[str] = None,
        api_base_url: str = "https://api.github.com",
    ):
        self.app_id = app_id or get_secret("github-app-id")
        self.private_key_pem = private_key_pem or get_secret("github-app-private-key")
        self.fallback_token = fallback_token or get_secret("github-token")
        self.api_base_url = api_base_url.rstrip("/")

        # Cache: installation_id -> (token, expire_timestamp)
        self._token_cache: Dict[int, Tuple[str, float]] = {}

    @property
    def is_app_configured(self) -> bool:
        """Returns True if App ID and Private Key are present."""
        return bool(self.app_id and self.private_key_pem)

    def clear_cache(self) -> None:
        """Clears the cached installation tokens."""
        self._token_cache.clear()

    def invalidate_token(self, installation_id: Optional[int] = None) -> None:
        """Evicts cached installation token so the next call forces a fresh exchange."""
        if installation_id is not None:
            self._token_cache.pop(installation_id, None)
        else:
            self._token_cache.clear()

    async def get_installation_token(
        self,
        installation_id: Optional[int] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Optional[str]:
        """Returns a valid installation access token or falls back to standard PAT.

        1. Checks in-memory cache for valid token.
        2. Mints a new token from GitHub API using App JWT if configured.
        3. Falls back to fallback_token (PAT).
        """
        fallback = self.fallback_token or get_secret("github-token")

        # If GitHub App is not configured or no installation_id provided, use PAT
        if not self.is_app_configured or installation_id is None:
            return fallback

        # 1. Check Cache
        now = time.time()
        if installation_id in self._token_cache:
            cached_token, expire_time = self._token_cache[installation_id]
            # 60s safety buffer before expiry
            if expire_time - now > 60:
                return cached_token

        # 2. Exchange App JWT for Installation Token
        try:
            app_id = self.app_id or get_secret("github-app-id")
            priv_key = self.private_key_pem or get_secret("github-app-private-key")
            jwt = generate_app_jwt(app_id, priv_key)  # type: ignore
            url = f"{self.api_base_url}/app/installations/{installation_id}/access_tokens"
            headers = {
                "Authorization": f"Bearer {jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            owns_client = False
            if client is None:
                client = httpx.AsyncClient(timeout=10.0)
                owns_client = True

            try:
                resp = await client.post(url, headers=headers)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    token = data.get("token")
                    expires_at_str = data.get("expires_at")

                    if expires_at_str:
                        # Parse ISO 8601 e.g. "2026-11-07T12:00:00Z"
                        dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                        expire_ts = dt.timestamp()
                    else:
                        expire_ts = now + 3500.0  # default ~1 hr

                    if token:
                        self._token_cache[installation_id] = (token, expire_ts)
                        logger.info("Successfully minted GitHub App installation token for ID %s", installation_id)
                        return token
                else:
                    logger.warning(
                        "GitHub App token exchange failed with status %d: %s. Falling back to PAT.",
                        resp.status_code,
                        resp.text,
                    )
            finally:
                if owns_client:
                    await client.aclose()

        except Exception as e:
            logger.error("Error creating GitHub App installation token: %s", e)

        # Fallback to PAT if token exchange fails
        return fallback
