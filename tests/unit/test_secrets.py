"""Unit tests for secure credential management via get_secret."""

from unittest.mock import MagicMock, patch
import pytest

from risk_agent.secrets import (
    clear_secret_cache,
    get_secret,
)


@pytest.fixture(autouse=True)
def reset_cache():
    clear_secret_cache()
    yield
    clear_secret_cache()


def test_get_secret_from_env_var_alias(monkeypatch):
    """Verifies retrieval from environment variable aliases (Cloud Run mounted secrets)."""
    # Test GOOGLE_API_KEY alias
    monkeypatch.setenv("GOOGLE_API_KEY", "test-google-key-123")
    assert get_secret("google-api-key") == "test-google-key-123"

    clear_secret_cache()
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_CLOUD_API_KEY", "test-google-cloud-key-456")
    assert get_secret("google-api-key") == "test-google-cloud-key-456"

    # Test GITHUB_WEBHOOK_SECRET
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "whsec_test_secret")
    assert get_secret("github-webhook-secret") == "whsec_test_secret"

    # Test GITHUB_TOKEN
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token")
    assert get_secret("github-token") == "ghp_test_token"


def test_get_secret_in_memory_cache(monkeypatch):
    """Verifies that secrets are cached in memory after first retrieval."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "initial-secret")
    val1 = get_secret("github-webhook-secret")
    assert val1 == "initial-secret"

    # Change environment variable: cache should return the cached value
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "changed-secret")
    val2 = get_secret("github-webhook-secret")
    assert val2 == "initial-secret"

    # After clearing cache, new value is retrieved
    clear_secret_cache()
    val3 = get_secret("github-webhook-secret")
    assert val3 == "changed-secret"


def test_get_secret_gcp_secret_manager_fallback(monkeypatch):
    """Verifies fallback to GCP Secret Manager API when environment variable is unset."""
    for key in ["GOOGLE_API_KEY", "GOOGLE_CLOUD_API_KEY", "GEMINI_API_KEY"]:
        monkeypatch.delenv(key, raising=False)

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.payload.data = b"secret-from-gcp-manager"
    mock_client.access_secret_version.return_value = mock_response

    with patch("risk_agent.secrets.secretmanager.SecretManagerServiceClient", return_value=mock_client):
        val = get_secret("google-api-key", project_id="dependency-impact-analyzer")
        assert val == "secret-from-gcp-manager"
        mock_client.access_secret_version.assert_called_once_with(
            request={"name": "projects/dependency-impact-analyzer/secrets/google-api-key/versions/latest"}
        )
