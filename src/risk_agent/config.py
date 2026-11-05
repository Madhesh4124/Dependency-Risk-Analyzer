"""Global configuration and security constraints for Dependency Upgrade Risk Agent."""

from typing import List, Set
from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    """Runtime configuration model."""

    # Release-Note Fetcher Allowlist
    allowlisted_hosts: Set[str] = Field(
        default_factory=lambda: {
            "pypi.org",
            "api.github.com",
            "raw.githubusercontent.com",
        }
    )

    # HTTP limits
    http_timeout_seconds: float = 10.0
    http_max_response_bytes: int = 500_000  # 500 KB cap

    # Quote Verifier Floor
    min_quote_token_length: int = 6

    # AST Scanner limits
    scanner_max_file_bytes: int = 1_000_000  # 1 MB
    scanner_max_file_count: int = 1000
    scanner_timeout_seconds: float = 30.0

    # Policy Engine Floors
    major_bump_verdict_floor: str = "REVIEW"  # Controlled by D-01 checkpoint

    # Webhook limits
    webhook_max_payload_bytes: int = 10_000_000  # 10 MB cap


DEFAULT_CONFIG = AgentConfig()

