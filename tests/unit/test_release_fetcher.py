"""Unit tests for ReleaseNoteFetcher security, allowlisting, and timeout policies."""

import pytest
import httpx
from risk_agent.fetcher.release_fetcher import ReleaseNoteFetcher, FetcherSecurityError


class TestReleaseNoteFetcherSecurity:
    def test_allowlist_enforcement(self):
        fetcher = ReleaseNoteFetcher(allowlisted_hosts={"pypi.org", "api.github.com"})

        # Allowed
        assert fetcher.is_host_allowed("https://pypi.org/pypi/requests/json") is True
        assert fetcher.is_host_allowed("https://api.github.com/repos/psf/requests/releases") is True

        # Disallowed
        assert fetcher.is_host_allowed("https://evil.com/payload") is False
        assert fetcher.is_host_allowed("https://attacker.org/release_notes") is False

        with pytest.raises(FetcherSecurityError) as exc_info:
            fetcher.fetch_url("https://evil.com/payload")
        assert "not in the allowlist" in str(exc_info.value)

    def test_redirect_rejection(self, monkeypatch):
        fetcher = ReleaseNoteFetcher(allowlisted_hosts={"api.github.com"})

        # Mock client to return redirect to evil domain
        def mock_get(client_self, url, *args, **kwargs):
            if "api.github.com" in str(url):
                return httpx.Response(
                    status_code=302,
                    headers={"location": "https://malicious-external-site.com/notes"},
                    request=httpx.Request("GET", str(url)),
                )
            return httpx.Response(status_code=200, text="hacked", request=httpx.Request("GET", str(url)))

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        with pytest.raises(FetcherSecurityError) as exc_info:
            fetcher.fetch_url("https://api.github.com/repos/org/repo/releases")
        assert "Cross-host redirect" in str(exc_info.value)

    def test_response_size_cap(self, monkeypatch):
        fetcher = ReleaseNoteFetcher(
            allowlisted_hosts={"pypi.org"},
            max_bytes=1000,
        )

        oversized_content = "x" * 2000

        def mock_get(client_self, url, *args, **kwargs):
            return httpx.Response(
                status_code=200,
                text=oversized_content,
                request=httpx.Request("GET", str(url)),
            )

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        with pytest.raises(FetcherSecurityError) as exc_info:
            fetcher.fetch_url("https://pypi.org/pypi/test/json")
        assert "exceeds cap" in str(exc_info.value)

    def test_timeout_handling(self, monkeypatch):
        fetcher = ReleaseNoteFetcher(allowlisted_hosts={"pypi.org"})

        def mock_timeout(client_self, url, *args, **kwargs):
            raise httpx.TimeoutException("Connection timed out")

        monkeypatch.setattr(httpx.Client, "get", mock_timeout)

        snapshot = fetcher.fetch_url("https://pypi.org/pypi/requests/json")
        assert snapshot.is_available is False
        assert snapshot.status_code == 408
