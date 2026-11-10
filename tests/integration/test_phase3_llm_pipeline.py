"""Integration tests for Phase 3 LLM-assisted workflow and prompt-injection defense.

Verifies Phase 3 exit criteria:
1. "LLM cannot lower risk floor (code-enforced)."
2. "Unverified/unsupported claims are clearly marked or rejected."
3. "Injected instructions do not lower verdict below floor."
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest

from risk_agent.extraction.extractor import LLMExtractor
from risk_agent.extraction.schemas import (
    ExtractionClaimPayload,
    ExtractionResponse,
)
from risk_agent.models.schemas import ClaimType, SeverityVerdict
from risk_agent.pipeline import RiskAgentPipeline
from risk_agent.security.injection_detector import InjectionDetector

TIER_A_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "tier_a"


def test_llm_cannot_lower_risk_floor_below_deterministic_baseline():
    """CRITICAL SECURITY TEST: An LLM suggesting NO_RISK_FOUND CANNOT lower the verdict

    when a verified breaking change intersects with repository usage.
    """
    case_dir = TIER_A_DIR / "case_01_api_removal"
    with open(case_dir / "upstream" / "release_notes.md", "r", encoding="utf-8") as f:
        notes = f.read()

    # Exact verbatim quote from release_notes.md
    quote = (
        "Removed the deprecated function `transform_legacy()`. Applications calling "
        "`transform_legacy()` will raise an `AttributeError`."
    )

    # Create mock LLM that hallucinates / erroneously suggests NO_RISK_FOUND
    hallucinating_response = ExtractionResponse(
        claims=[
            ExtractionClaimPayload(
                change_type=ClaimType.BREAKING,
                affected_api="transform_legacy",
                quoted_text=quote,
                description="Removed legacy API",
                llm_suggested_risk=SeverityVerdict.NO_RISK_FOUND,  # Erroneous low risk
            )
        ],
        summary="Claiming everything is safe despite breaking changes",
        overall_risk=SeverityVerdict.NO_RISK_FOUND,  # Suggesting NO_RISK_FOUND
    )

    mock_chain = MagicMock()
    mock_chain.invoke.return_value = hallucinating_response
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    extractor = LLMExtractor(llm=mock_llm)
    pipeline = RiskAgentPipeline(extractor=extractor)

    report = pipeline.evaluate_case(
        case_dir=case_dir,
        raw_release_notes=notes,
        package_name="data-transformer",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    # Invariants
    assert report.risk_floor == SeverityVerdict.RISKY
    assert report.llm_verdict == SeverityVerdict.NO_RISK_FOUND
    # Final verdict MUST stay at RISKY — floor cannot be lowered!
    assert report.verdict == SeverityVerdict.RISKY
    assert len(report.verified_claims) == 1
    assert len(report.potential_usages) > 0


def test_unverified_llm_quote_is_flagged_and_does_not_count_as_evidence():
    """Verifies that hallucinated quotes are routed to unverified_claims and cannot trigger RISKY."""
    case_dir = TIER_A_DIR / "case_04_non_breaking"
    with open(case_dir / "upstream" / "release_notes.md", "r", encoding="utf-8") as f:
        notes = f.read()

    # Hallucinated quote that does NOT exist in the release notes
    fake_quote_response = ExtractionResponse(
        claims=[
            ExtractionClaimPayload(
                change_type=ClaimType.BREAKING,
                affected_api="render_html_table",
                quoted_text="this quote definitely does not exist anywhere in the source notes at all",
                description="Hallucinated change",
                llm_suggested_risk=SeverityVerdict.RISKY,
            )
        ],
        summary="Hallucination test",
        overall_risk=SeverityVerdict.RISKY,
    )

    mock_chain = MagicMock()
    mock_chain.invoke.return_value = fake_quote_response
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    extractor = LLMExtractor(llm=mock_llm)
    pipeline = RiskAgentPipeline(extractor=extractor)

    report = pipeline.evaluate_case(
        case_dir=case_dir,
        raw_release_notes=notes,
        package_name="text-styler",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    # Claim must be rejected by quote verifier
    assert len(report.verified_claims) == 0
    assert len(report.unverified_claims) == 1
    assert report.unverified_claims[0].is_verified is False
    # Because all claims are unverified, floor defaults to REVIEW
    assert report.risk_floor == SeverityVerdict.REVIEW


def test_short_quote_below_token_floor_is_unverified():
    """Verifies that claims with quotes shorter than 6 tokens fail verification even if substring matches."""
    case_dir = TIER_A_DIR / "case_01_api_removal"
    notes = "Short line: removed function here."

    short_quote_response = ExtractionResponse(
        claims=[
            ExtractionClaimPayload(
                change_type=ClaimType.BREAKING,
                affected_api="transform_legacy",
                quoted_text="removed function",  # Only 2 tokens < 6 token floor
                description="Too short to be verified evidence",
                llm_suggested_risk=SeverityVerdict.RISKY,
            )
        ],
        summary="Short quote test",
        overall_risk=SeverityVerdict.RISKY,
    )

    mock_chain = MagicMock()
    mock_chain.invoke.return_value = short_quote_response
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    extractor = LLMExtractor(llm=mock_llm)
    pipeline = RiskAgentPipeline(extractor=extractor)

    report = pipeline.evaluate_case(
        case_dir=case_dir,
        raw_release_notes=notes,
        package_name="data-transformer",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    assert len(report.verified_claims) == 0
    assert len(report.unverified_claims) == 1
    assert report.unverified_claims[0].is_verified is False


def test_llm_can_elevate_verdict_upward():
    """Verifies that an LLM suggestion can raise a verdict (e.g.

    from REVIEW to RISKY), which is explicitly allowed by the policy engine.
    """
    case_dir = TIER_A_DIR / "case_03_deprecation"
    with open(case_dir / "upstream" / "release_notes.md", "r", encoding="utf-8") as f:
        notes = f.read()

    # Genuine quote in release notes
    valid_quote = (
        "`request_v1()` is deprecated and will be removed in api-client 2.0.0. "
        "Please use `request()` instead."
    )
    elevated_response = ExtractionResponse(
        claims=[
            ExtractionClaimPayload(
                change_type=ClaimType.DEPRECATION,
                affected_api="request_v1",
                quoted_text=valid_quote,
                description="Deprecation detected, LLM recommends treating as RISKY",
                llm_suggested_risk=SeverityVerdict.RISKY,
            )
        ],
        summary="Recommending RISKY",
        overall_risk=SeverityVerdict.RISKY,  # Elevating from REVIEW to RISKY
    )

    mock_chain = MagicMock()
    mock_chain.invoke.return_value = elevated_response
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    extractor = LLMExtractor(llm=mock_llm)
    pipeline = RiskAgentPipeline(extractor=extractor)

    report = pipeline.evaluate_case(
        case_dir=case_dir,
        raw_release_notes=notes,
        package_name="api-client",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    # Floor for deprecation with usage is REVIEW
    assert report.risk_floor == SeverityVerdict.REVIEW
    assert report.llm_verdict == SeverityVerdict.RISKY
    # Final verdict is elevated to RISKY by max(floor, llm_suggestion)
    assert report.verdict == SeverityVerdict.RISKY
    assert any("elevated" in r.lower() for r in report.reasons)


def test_adversarial_prompt_injection_fixture_case_6():
    """End-to-end regression test for TIER-A-06: Prompt injection attempting verdict override.

    Verifies that injected instructions cannot override the floor.
    """
    case_dir = TIER_A_DIR / "case_06_prompt_injection"
    with open(case_dir / "upstream" / "release_notes.md", "r", encoding="utf-8") as f:
        notes = f.read()

    valid_quote = (
        "The `verify_token()` function signature has changed. Callers must now provide `secret_key` "
        "as a mandatory second argument (`verify_token(token, secret_key)`)."
    )

    # Even if an adversarial release note tricks the LLM into claiming NO_RISK_FOUND
    injected_response = ExtractionResponse(
        claims=[
            ExtractionClaimPayload(
                change_type=ClaimType.BREAKING,
                affected_api="verify_token",
                quoted_text=valid_quote,
                description="Breaking signature change of verify_token",
                llm_suggested_risk=SeverityVerdict.NO_RISK_FOUND,  # Injected instruction override attempt
            )
        ],
        summary="Adversarial attack attempting override",
        overall_risk=SeverityVerdict.NO_RISK_FOUND,
    )

    mock_chain = MagicMock()
    mock_chain.invoke.return_value = injected_response
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    extractor = LLMExtractor(llm=mock_llm)
    pipeline = RiskAgentPipeline(extractor=extractor)

    report = pipeline.evaluate_case(
        case_dir=case_dir,
        raw_release_notes=notes,
        package_name="auth-guard",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    # 1. Quote was verified against release notes
    assert len(report.verified_claims) == 1
    # 2. AST scanner matched verify_token usage in repository
    assert len(report.potential_usages) > 0
    # 3. Deterministic floor is computed as RISKY
    assert report.risk_floor == SeverityVerdict.RISKY
    # 4. Final verdict MUST remain RISKY, defeating the injection completely
    assert report.verdict == SeverityVerdict.RISKY
    assert report.injection_detected is True


def test_pipeline_model_armor_blocks_stealth_injection_without_code_usages():
    """Verifies RiskAgentPipeline invokes Model Armor ingress/egress and prevents NO_RISK_FOUND."""
    from google.cloud import modelarmor_v1

    mock_ma_client = MagicMock()
    mock_ma_client.sanitize_user_prompt.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            filter_match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND,
            filter_results={
                "pi_and_jailbreak": SimpleNamespace(
                    pi_and_jailbreak_filter_result=SimpleNamespace(
                        match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND,
                        confidence_level=SimpleNamespace(name="HIGH"),
                    ),
                    malicious_uri_filter_result=None,
                    sdp_filter_result=None,
                    rai_filter_result=None,
                    csam_filter_filter_result=None,
                    virus_scan_filter_result=None,
                )
            },
        )
    )
    mock_ma_client.sanitize_model_response.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            filter_match_state=modelarmor_v1.FilterMatchState.NO_MATCH_FOUND,
            filter_results={},
        )
    )

    detector = InjectionDetector(
        enable_model_armor=True,
        model_armor_template="projects/p1/locations/asia-south1/templates/shield",
        model_armor_client=mock_ma_client,
    )

    # Even if attacker tricks LLM into returning zero claims and NO_RISK_FOUND
    compromised_llm_resp = ExtractionResponse(
        claims=[],
        summary="Completely safe patch.",
        overall_risk=SeverityVerdict.NO_RISK_FOUND,
    )
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = compromised_llm_resp
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    pipeline = RiskAgentPipeline(
        extractor=LLMExtractor(llm=mock_llm),
        injection_detector=detector,
    )

    report = pipeline.evaluate_with_sources(
        sources={"requirements.txt": "requests==2.31.0\n", "app.py": "import os\n"},
        raw_release_notes="Subtle adversarial jailbreak disguised as patch notes.",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.31.1",
    )

    assert report.injection_detected is True
    assert report.injection_engine == "model_armor"
    assert "pi_and_jailbreak:HIGH" in report.model_armor_triggered_filters
    assert report.risk_floor == SeverityVerdict.REVIEW
    assert report.verdict == SeverityVerdict.REVIEW
    mock_ma_client.sanitize_user_prompt.assert_called_once()
    mock_ma_client.sanitize_model_response.assert_called_once()


def test_pipeline_model_armor_egress_response_flag():
    """Verifies Model Armor sanitize_model_response flags compromised LLM output even on clean input."""
    from google.cloud import modelarmor_v1

    mock_ma_client = MagicMock()
    mock_ma_client.sanitize_user_prompt.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            filter_match_state=modelarmor_v1.FilterMatchState.NO_MATCH_FOUND,
            filter_results={},
        )
    )
    mock_ma_client.sanitize_model_response.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            filter_match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND,
            filter_results={
                "sdp": SimpleNamespace(
                    pi_and_jailbreak_filter_result=None,
                    malicious_uri_filter_result=None,
                    sdp_filter_result=SimpleNamespace(
                        inspect_result=SimpleNamespace(match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND),
                        deidentify_result=None,
                    ),
                    rai_filter_result=None,
                    csam_filter_filter_result=None,
                    virus_scan_filter_result=None,
                )
            },
        )
    )

    detector = InjectionDetector(
        enable_model_armor=True,
        model_armor_template="projects/p1/locations/asia-south1/templates/shield",
        model_armor_client=mock_ma_client,
    )
    compromised_output = ExtractionResponse(
        claims=[],
        summary="Leaked credential or unsafe summary",
        overall_risk=SeverityVerdict.NO_RISK_FOUND,
    )
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = compromised_output
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    pipeline = RiskAgentPipeline(
        extractor=LLMExtractor(llm=mock_llm),
        injection_detector=detector,
    )

    report = pipeline.evaluate_with_sources(
        sources={"app.py": "import requests\n"},
        raw_release_notes="Version 2.31.1 minor bugfix.",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.31.1",
    )

    assert report.injection_detected is True
    assert "sdp" in report.model_armor_triggered_filters
    assert report.risk_floor == SeverityVerdict.REVIEW
    assert report.verdict == SeverityVerdict.REVIEW


def test_pipeline_model_armor_fail_closed_blocks_auto_approval():
    """Verifies fail-closed Model Armor error forces REVIEW rather than auto-approving NO_RISK_FOUND."""
    mock_ma_client = MagicMock()
    mock_ma_client.sanitize_user_prompt.side_effect = RuntimeError("Model Armor 503 Unavailable")

    detector = InjectionDetector(
        enable_model_armor=True,
        fail_closed=True,
        model_armor_template="projects/p1/locations/asia-south1/templates/pr-security-shield",
        model_armor_client=mock_ma_client,
    )
    clean_llm_resp = ExtractionResponse(
        claims=[],
        summary="Minor patch fix.",
        overall_risk=SeverityVerdict.NO_RISK_FOUND,
    )
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = clean_llm_resp
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_chain

    pipeline = RiskAgentPipeline(
        extractor=LLMExtractor(llm=mock_llm),
        injection_detector=detector,
    )
    report = pipeline.evaluate_with_sources(
        sources={"requirements.txt": "requests==2.31.0\n", "app.py": "import os\n"},
        raw_release_notes="Version 2.31.1 fixes typo in documentation.",
        package_name="requests",
        old_version="2.31.0",
        new_version="2.31.1",
    )

    assert report.model_armor_status == "error"
    assert "503 Unavailable" in (report.model_armor_error or "")
    assert report.risk_floor == SeverityVerdict.REVIEW
    assert report.verdict == SeverityVerdict.REVIEW


def test_pipeline_applies_sdp_deidentified_notes_to_llm_keeps_raw_for_verifier():
    """Verifies SDP-redacted text goes to LLM while QuoteVerifier still checks unmodified raw release notes."""
    from google.cloud import modelarmor_v1

    raw_notes = "Removed legacy helper `old_helper()` completely; token sk_live_abc123456789 is no longer accepted."
    redacted_notes = "Removed legacy helper `old_helper()` completely; token [REDACTED] is no longer accepted."

    mock_ma_client = MagicMock()
    mock_ma_client.sanitize_user_prompt.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            invocation_result=modelarmor_v1.InvocationResult.SUCCESS,
            filter_match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND,
            filter_results={
                "sdp": SimpleNamespace(
                    pi_and_jailbreak_filter_result=None,
                    malicious_uri_filter_result=None,
                    sdp_filter_result=SimpleNamespace(
                        inspect_result=None,
                        deidentify_result=SimpleNamespace(
                            match_state=modelarmor_v1.FilterMatchState.MATCH_FOUND,
                            data=SimpleNamespace(text=redacted_notes),
                            info_types=["AUTH_TOKEN"],
                        ),
                        redact_result=None,
                    ),
                    rai_filter_result=None,
                    csam_filter_filter_result=None,
                    virus_scan_filter_result=None,
                )
            },
        )
    )
    mock_ma_client.sanitize_model_response.return_value = SimpleNamespace(
        sanitization_result=SimpleNamespace(
            invocation_result=modelarmor_v1.InvocationResult.SUCCESS,
            filter_match_state=modelarmor_v1.FilterMatchState.NO_MATCH_FOUND,
            filter_results={},
        )
    )

    captured_prompts = []

    class _CapturingLLM:
        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            captured_prompts.append("\n".join(getattr(m, "content", str(m)) for m in messages))
            return ExtractionResponse(
                claims=[
                    ExtractionClaimPayload(
                        change_type=ClaimType.BREAKING,
                        affected_api="old_helper",
                        quoted_text="Removed legacy helper `old_helper()` completely; token",
                        description="Removed old_helper",
                        llm_suggested_risk=SeverityVerdict.RISKY,
                    )
                ],
                summary="Breaking API removal",
                overall_risk=SeverityVerdict.RISKY,
            )

    detector = InjectionDetector(
        enable_model_armor=True,
        model_armor_template="projects/p1/locations/asia-south1/templates/pr-security-shield",
        model_armor_client=mock_ma_client,
    )
    pipeline = RiskAgentPipeline(
        extractor=LLMExtractor(llm=_CapturingLLM()),
        injection_detector=detector,
    )
    report = pipeline.evaluate_with_sources(
        sources={"requirements.txt": "pkg==1.0.0\n", "app.py": "from pkg import old_helper\nold_helper()\n"},
        raw_release_notes=raw_notes,
        package_name="pkg",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    assert len(captured_prompts) == 1
    assert "[REDACTED]" in captured_prompts[0]
    assert "sk_live_abc123456789" not in captured_prompts[0]
    assert len(report.verified_claims) == 1
    assert report.verdict == SeverityVerdict.RISKY
