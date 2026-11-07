"""Unit tests for Phase 6 PR Comment Markdown Formatter."""

import pytest
from risk_agent.models.schemas import (
    ConfidenceTier,
    ExtractedClaim,
    ClaimType,
    RiskReport,
    SeverityVerdict,
    UsageMatch,
    VersionBumpType,
)
from risk_agent.security.injection_detector import InjectionPatternType, InjectionResult
from risk_agent.webhook.pr_commenter import REPORT_SIGNATURE, format_pr_comment, is_library_docs_url


@pytest.fixture
def sample_report():
    return RiskReport(
        package_name="pydantic",
        old_version="1.10.12",
        new_version="2.6.0",
        bump_type=VersionBumpType.MAJOR,
        verdict=SeverityVerdict.RISKY,
        risk_floor=SeverityVerdict.REVIEW,
        reasons=["Breaking changes detected in pydantic with matching repo usages."],
        verified_claims=[
            ExtractedClaim(
                claim_id="C1",
                claim_type=ClaimType.BREAKING,
                affected_api="BaseModel.parse_obj",
                quoted_text="parse_obj was removed in v2.0 in favor of model_validate",
                is_verified=True,
            )
        ],
        potential_usages=[
            UsageMatch(
                file_path="src/models/user.py",
                line_number=45,
                matched_symbol="BaseModel.parse_obj",
                match_type="direct_call",
                confidence_tier=ConfidenceTier.HIGH,
                code_snippet="user = User.parse_obj(payload)",
            )
        ],
        release_notes_available=True,
        source_url="https://github.com/pydantic/pydantic/releases",
        documentation_url="https://docs.pydantic.dev/latest/changelog/",
        model_id="gemini-2.0-flash",
    )


def test_format_pr_comment_signature_and_headers(sample_report):
    """Verifies that signature marker and clean, emoji-free headers and doc links are included."""
    comment = format_pr_comment(sample_report, delivery_id="deliv-12345", execution_latency_ms=350.2)

    assert REPORT_SIGNATURE in comment
    assert "## Dependency Impact: HIGH RISK" in comment
    assert "`pydantic`" in comment
    assert "`1.10.12` -> `2.6.0`" in comment
    assert "deliv-12345" in comment
    assert "350.2 ms" in comment
    assert "src/models/user.py" in comment
    assert "parse_obj was removed" in comment
    # Grounded link to official library docs
    assert "[Verify in Docs](https://docs.pydantic.dev/latest/changelog/)" in comment


def test_format_pr_comment_with_injection_warning(sample_report):
    """Verifies that the > [!WARNING] banner appears without emojis when prompt injection is detected."""
    injection = InjectionResult(
        detected=True,
        pattern_type=InjectionPatternType.INSTRUCTION_RESET,
        matched_snippet="ignore previous instructions",
        sanitized_snippet="ignore previous instructions",
        confidence=0.95,
        engine="local_heuristic",
    )

    comment = format_pr_comment(sample_report, injection_result=injection)

    assert "> [!WARNING]" in comment
    assert "Security Tripwire: Adversarial Prompt Injection Detected & Quarantined" in comment
    assert "INSTRUCTION_RESET" in comment
    assert "ignore previous instructions" in comment


def test_format_pr_comment_clean_no_risk():
    """Verifies comment layout for clean NO_RISK_FOUND report without injection and without emojis."""
    clean_report = RiskReport(
        package_name="requests",
        old_version="2.28.0",
        new_version="2.28.2",
        bump_type=VersionBumpType.PATCH,
        verdict=SeverityVerdict.NO_RISK_FOUND,
        risk_floor=SeverityVerdict.NO_RISK_FOUND,
        reasons=["Minor patch with no breaking changes."],
        verified_claims=[],
        potential_usages=[],
        release_notes_available=True,
    )

    comment = format_pr_comment(clean_report, injection_result=None)

    assert "## Dependency Impact: NO_RISK_FOUND" in comment
    assert "> [!WARNING]" not in comment
    assert "_No direct affected usages detected in repository source files._" in comment


def test_is_library_docs_url():
    """Verifies library docs URL filtering logic."""
    assert is_library_docs_url("https://docs.pydantic.dev/latest/changelog/") is True
    assert is_library_docs_url("https://urllib3.readthedocs.io/en/latest/v2-migration-guide.html") is True
    assert is_library_docs_url("https://pypi.org/project/pydantic/2.6.0/") is False
    assert is_library_docs_url(None) is False
    assert is_library_docs_url("") is False
