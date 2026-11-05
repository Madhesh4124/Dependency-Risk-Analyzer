"""Release-note fetcher with strict domain allowlisting and redirect protection."""

import datetime
import logging
from typing import Optional, Set
from urllib.parse import urlparse
import httpx
from risk_agent.config import DEFAULT_CONFIG
from risk_agent.models.schemas import ReleaseNoteSnapshot

logger = logging.getLogger(__name__)


class FetcherSecurityError(Exception):
    """Raised when an outbound HTTP request violates security constraints."""
    pass


class ReleaseNoteFetcher:
    """Fetches release notes from allowlisted public sources."""

    def __init__(
        self,
        allowlisted_hosts: Optional[Set[str]] = None,
        timeout_seconds: float = DEFAULT_CONFIG.http_timeout_seconds,
        max_bytes: int = DEFAULT_CONFIG.http_max_response_bytes,
    ):
        self.allowlisted_hosts = (
            allowlisted_hosts
            if allowlisted_hosts is not None
            else DEFAULT_CONFIG.allowlisted_hosts
        )
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def is_host_allowed(self, url: str) -> bool:
        """Checks whether the URL host is in the allowlist."""
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0]  # Strip port if present
        return host in self.allowlisted_hosts

    def fetch_url(self, url: str, max_redirects: int = 3) -> ReleaseNoteSnapshot:
        """Fetches raw content from an allowlisted URL with redirect protection.

        Raises:
            FetcherSecurityError: If host is not allowlisted, redirect escapes allowlist,
                                  or response exceeds max_bytes.
        """
        current_url = url
        redirect_count = 0

        with httpx.Client(timeout=self.timeout_seconds, follow_redirects=False) as client:
            while redirect_count <= max_redirects:
                if not self.is_host_allowed(current_url):
                    raise FetcherSecurityError(
                        f"URL host '{urlparse(current_url).netloc}' is not in the allowlist"
                    )

                try:
                    response = client.get(current_url)
                except httpx.TimeoutException as e:
                    logger.warning("Timeout fetching %s: %s", current_url, e)
                    return ReleaseNoteSnapshot(
                        package_name="",
                        version="",
                        raw_content="",
                        source_url=current_url,
                        is_available=False,
                        status_code=408,
                    )
                except httpx.RequestError as e:
                    logger.warning("Request error fetching %s: %s", current_url, e)
                    return ReleaseNoteSnapshot(
                        package_name="",
                        version="",
                        raw_content="",
                        source_url=current_url,
                        is_available=False,
                        status_code=500,
                    )

                # Check for redirects
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        break
                    # Resolve relative redirect
                    target_url = httpx.URL(current_url).join(location)
                    target_url_str = str(target_url)

                    # Verify redirect target host is allowlisted
                    if not self.is_host_allowed(target_url_str):
                        raise FetcherSecurityError(
                            f"Cross-host redirect to disallowed host '{urlparse(target_url_str).netloc}' rejected"
                        )
                    current_url = target_url_str
                    redirect_count += 1
                    continue

                # Enforce size limit
                content_len = len(response.content)
                if content_len > self.max_bytes:
                    raise FetcherSecurityError(
                        f"Response size ({content_len} bytes) exceeds cap ({self.max_bytes} bytes)"
                    )

                is_ok = 200 <= response.status_code < 300
                return ReleaseNoteSnapshot(
                    package_name="",
                    version="",
                    raw_content=response.text if is_ok else "",
                    source_url=current_url,
                    retrieval_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    is_available=is_ok and bool(response.text.strip()),
                    status_code=response.status_code,
                )

        raise FetcherSecurityError("Exceeded maximum redirect limit")

    def fetch_pypi_release_notes(self, package_name: str, version: str) -> ReleaseNoteSnapshot:
        """Fetches release description from the official PyPI JSON API."""
        url = f"https://pypi.org/pypi/{package_name}/json"
        snapshot = self.fetch_url(url)
        snapshot.package_name = package_name
        snapshot.version = version

        if snapshot.is_available and snapshot.raw_content:
            try:
                import json
                data = json.loads(snapshot.raw_content)
                # Check description in info
                info = data.get("info", {})
                description = info.get("description", "")
                snapshot.raw_content = description
                snapshot.is_available = bool(description.strip())
            except Exception as e:
                logger.warning("Failed to parse PyPI JSON for %s: %s", package_name, e)
                snapshot.is_available = False

        return snapshot
