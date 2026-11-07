"""Secure credentials management via GCP Secret Manager and environment variables."""

import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from google.cloud import secretmanager
    HAS_SECRET_MANAGER = True
except ImportError:
    HAS_SECRET_MANAGER = False

# In-memory cache for retrieved secrets to avoid repeated network latency and quota usage
_SECRET_CACHE: Dict[str, str] = {}

# Canonical mapping of secret names to environment variable aliases
SECRET_ENV_ALIASES: Dict[str, List[str]] = {
    "google-api-key": [
        "GOOGLE_API_KEY",
        "GOOGLE_CLOUD_API_KEY",
        "GEMINI_API_KEY",
    ],
    "github-webhook-secret": [
        "GITHUB_WEBHOOK_SECRET",
        "WEBHOOK_SECRET",
    ],
    "github-token": [
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_PAT",
    ],
}


def clear_secret_cache() -> None:
    """Clears the in-memory secret cache (useful for testing and key rotations)."""
    _SECRET_CACHE.clear()


def get_secret(
    secret_name: str,
    project_id: Optional[str] = None,
    default_env_var: Optional[str] = None,
) -> Optional[str]:
    """Retrieves secret value prioritizing:

    1. In-memory cache
    2. Cloud Run mounted secret environment variables (and standard aliases)
    3. Direct GCP Secret Manager API lookup via Application Default Credentials
    Never logs secret values.
    """
    # 1. Check in-memory cache
    if secret_name in _SECRET_CACHE:
        return _SECRET_CACHE[secret_name]

    # 2. Check environment variables (Cloud Run secret mount or local .env)
    candidate_env_vars: List[str] = []
    if default_env_var:
        candidate_env_vars.append(default_env_var)

    # Check known aliases
    aliases = SECRET_ENV_ALIASES.get(secret_name.lower().strip(), [])
    candidate_env_vars.extend(aliases)

    # Standard uppercase transformation (e.g. google-api-key -> GOOGLE_API_KEY)
    candidate_env_vars.append(secret_name.upper().replace("-", "_"))
    candidate_env_vars.append(secret_name)

    for env_key in candidate_env_vars:
        env_val = os.getenv(env_key)
        if env_val and env_val.strip():
            _SECRET_CACHE[secret_name] = env_val.strip()
            return _SECRET_CACHE[secret_name]

    # 3. Direct GCP Secret Manager API lookup
    if HAS_SECRET_MANAGER:
        pid = (
            project_id
            or os.getenv("GCP_PROJECT_ID")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or "dependency-impact-analyzer"
        )
        try:
            client = secretmanager.SecretManagerServiceClient()
            resource_name = f"projects/{pid}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(request={"name": resource_name})
            secret_value = response.payload.data.decode("UTF-8").strip()
            if secret_value:
                _SECRET_CACHE[secret_name] = secret_value
                logger.info(f"Retrieved secret '{secret_name}' from GCP Secret Manager (project: {pid})")
                return secret_value
        except Exception as e:
            # Check alternative naming in Secret Manager if not found
            if secret_name == "google-api-key":
                for alt_name in ["google-cloud-api-key", "gemini-api-key"]:
                    try:
                        resource_name = f"projects/{pid}/secrets/{alt_name}/versions/latest"
                        response = client.access_secret_version(request={"name": resource_name})
                        secret_value = response.payload.data.decode("UTF-8").strip()
                        if secret_value:
                            _SECRET_CACHE[secret_name] = secret_value
                            logger.info(f"Retrieved secret via alias '{alt_name}' from GCP Secret Manager")
                            return secret_value
                    except Exception:
                        pass

            logger.debug(f"Secret '{secret_name}' not accessible in Secret Manager ({e})")

    return None
