"""Unit tests for Verdict Policy Engine deterministic floor rules and severity ordering."""

import pytest
from risk_agent.models.schemas import (
    ClaimType,
    ConfidenceTier,
    ExtractedClaim,
    SeverityVerdict,
    UsageMatch,
    VersionBumpType,
)
from risk_agent.policy.policy_engine import PolicyEngine, escalate


class TestPolicyEngineFloors:
    def test_missing_release_notes_forces_review(self):
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.MINOR,
            release_notes_available=False,
            verified_claims=[],
            unverified_claims=[],
            usages=[],
        )
        assert floor == SeverityVerdict.REVIEW
        assert any("missing" in r for r in reasons)

    def test_verified_breaking_with_high_usage_forces_risky(self):
        breaking_claim = ExtractedClaim(
            claim_id="c1",
            claim_type=ClaimType.BREAKING,
            affected_api="data_transformer.transform_legacy",
            quoted_text="Removed transform_legacy in favor of transform.",
        )
        usage = UsageMatch(
            file_path="app.py",
            line_number=10,
            matched_symbol="transform_legacy",
            match_type="direct_call",
            confidence_tier=ConfidenceTier.HIGH,
        )
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.MAJOR,
            release_notes_available=True,
            verified_claims=[breaking_claim],
            unverified_claims=[],
            usages=[usage],
        )
        assert floor == SeverityVerdict.RISKY
        assert any("breaking" in r.lower() for r in reasons)

    def test_verified_breaking_with_medium_usage_forces_review(self):
        # Avoids false alarm on generic method names (e.g. .solve() or .get())
        breaking_claim = ExtractedClaim(
            claim_id="c1",
            claim_type=ClaimType.BREAKING,
            affected_api="math_solver.solve",
            quoted_text="Changed solve signature to require mode parameter.",
        )
        usage = UsageMatch(
            file_path="app.py",
            line_number=15,
            matched_symbol="solve",
            match_type="untyped_attribute_call",
            confidence_tier=ConfidenceTier.MEDIUM,
        )
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.MAJOR,
            release_notes_available=True,
            verified_claims=[breaking_claim],
            unverified_claims=[],
            usages=[usage],
        )
        assert floor == SeverityVerdict.REVIEW
        assert any("uncertain type resolution" in r for r in reasons)

    def test_deprecation_exercised_by_code_forces_review(self):
        deprecation_claim = ExtractedClaim(
            claim_id="c1",
            claim_type=ClaimType.DEPRECATION,
            affected_api="api_client.request_v1",
            quoted_text="request_v1 is deprecated and will be removed in 2.0.0.",
        )
        usage = UsageMatch(
            file_path="app.py",
            line_number=5,
            matched_symbol="request_v1",
            match_type="direct_call",
            confidence_tier=ConfidenceTier.HIGH,
        )
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.MINOR,
            release_notes_available=True,
            verified_claims=[deprecation_claim],
            unverified_claims=[],
            usages=[usage],
        )
        assert floor == SeverityVerdict.REVIEW
        assert any("deprecation" in r.lower() for r in reasons)

    def test_major_bump_clean_with_verified_notes_returns_no_risk_found(self):
        # Decision D-01 Option C: Major bump with complete notes & no breaking usages -> NO_RISK_FOUND
        breaking_unrelated_claim = ExtractedClaim(
            claim_id="c1",
            claim_type=ClaimType.BREAKING,
            affected_api="text_styler.render_html_table",
            quoted_text="Removed render_html_table in version 2.0.0.",
        )
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.MAJOR,
            release_notes_available=True,
            verified_claims=[breaking_unrelated_claim],
            unverified_claims=[],
            usages=[],  # 0 usages in code
        )
        assert floor == SeverityVerdict.NO_RISK_FOUND

    def test_prompt_injection_blocks_automatic_no_risk_found(self):
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.PATCH,
            release_notes_available=True,
            verified_claims=[],
            unverified_claims=[],
            usages=[],
            injection_detected=True,
        )
        assert floor == SeverityVerdict.REVIEW
        assert any("prompt injection" in r.lower() for r in reasons)

    def test_model_armor_error_forces_review_fail_closed(self):
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=VersionBumpType.PATCH,
            release_notes_available=True,
            verified_claims=[],
            unverified_claims=[],
            usages=[],
            model_armor_error=True,
        )
        assert floor == SeverityVerdict.REVIEW
        assert any("model armor" in r.lower() for r in reasons)


class TestVerdictEscalationAndFloorEnforcement:
    def test_policy_cannot_go_down(self):
        # Floor is RISKY; LLM suggests NO_RISK_FOUND (e.g. prompt injection attempt)
        final = PolicyEngine.compute_final_verdict(
            risk_floor=SeverityVerdict.RISKY,
            llm_verdict=SeverityVerdict.NO_RISK_FOUND,
        )
        assert final == SeverityVerdict.RISKY

    def test_llm_can_escalate_up(self):
        # Floor is REVIEW; LLM suggests RISKY
        final = PolicyEngine.compute_final_verdict(
            risk_floor=SeverityVerdict.REVIEW,
            llm_verdict=SeverityVerdict.RISKY,
        )
        assert final == SeverityVerdict.RISKY

    def test_escalate_helper(self):
        assert escalate(SeverityVerdict.NO_RISK_FOUND, SeverityVerdict.REVIEW) == SeverityVerdict.REVIEW
        assert escalate(SeverityVerdict.REVIEW, SeverityVerdict.RISKY) == SeverityVerdict.RISKY
        assert escalate(SeverityVerdict.RISKY, SeverityVerdict.NO_RISK_FOUND) == SeverityVerdict.RISKY

