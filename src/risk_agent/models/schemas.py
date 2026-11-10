"""Data models and schemas for Dependency Upgrade Risk Agent."""

import datetime
from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class VersionBumpType(str, Enum):
    PATCH = "PATCH"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    UNKNOWN = "UNKNOWN"


class DependencyBump(BaseModel):
    """Represents an extracted dependency update from a PR diff."""
    package_name: str
    old_version: str
    new_version: str
    manifest_file: str
    bump_type: VersionBumpType = VersionBumpType.UNKNOWN


class ReleaseNoteSnapshot(BaseModel):
    """Captured upstream release notes with source provenance."""
    package_name: str
    version: str
    raw_content: str
    source_url: str
    documentation_url: Optional[str] = None
    retrieval_timestamp: str = Field(default_factory=utc_now_iso)
    is_available: bool = True
    status_code: Optional[int] = 200


class ImportResolution(BaseModel):
    """Mapping from PyPI distribution name to Python module import name(s)."""
    distribution_name: str
    import_module_names: List[str]
    resolution_confidence: str = "high"  # "high" | "low"
    method_used: str = "metadata"  # "metadata" | "static_map" | "fallback"


class ConfidenceTier(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class UsageMatch(BaseModel):
    """A detected potential usage of an affected API in the repository."""
    file_path: str
    line_number: int
    matched_symbol: str
    match_type: str  # "direct_call", "from_import_call", "aliased_call", "attribute_access"
    confidence_tier: ConfidenceTier
    code_snippet: Optional[str] = None


class ClaimType(str, Enum):
    BREAKING = "BREAKING"
    DEPRECATION = "DEPRECATION"
    NON_BREAKING = "NON_BREAKING"
    INFO = "INFO"


class ExtractedClaim(BaseModel):
    """A claim about an API change extracted from release notes."""
    claim_id: str
    claim_type: ClaimType
    affected_api: Optional[str] = None
    quoted_text: str
    description: Optional[str] = None
    model_id: Optional[str] = None
    prompt_version: Optional[str] = None
    is_verified: Optional[bool] = None


class QuoteVerificationResult(BaseModel):
    """Result of verifying an extracted quote against raw release notes."""
    claim_id: str
    quoted_text: str
    is_verified: bool
    token_count: int
    failure_reason: Optional[str] = None


class SeverityVerdict(str, Enum):
    NO_RISK_FOUND = "NO_RISK_FOUND"
    REVIEW = "REVIEW"
    RISKY = "RISKY"


class RiskReport(BaseModel):
    """Final assessment report produced by the agent."""
    package_name: str
    old_version: str
    new_version: str
    bump_type: VersionBumpType
    verdict: SeverityVerdict
    risk_floor: SeverityVerdict
    llm_verdict: Optional[SeverityVerdict] = None
    reasons: List[str]
    verified_claims: List[ExtractedClaim] = Field(default_factory=list)
    unverified_claims: List[ExtractedClaim] = Field(default_factory=list)
    potential_usages: List[UsageMatch] = Field(default_factory=list)
    release_notes_available: bool = True
    source_url: Optional[str] = None
    documentation_url: Optional[str] = None
    model_id: Optional[str] = None
    prompt_version: Optional[str] = None
    injection_detected: bool = False
    injection_pattern: Optional[str] = None
    injection_engine: Optional[str] = None
    model_armor_status: Optional[str] = None
    model_armor_error: Optional[str] = None
    model_armor_triggered_filters: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=utc_now_iso)
