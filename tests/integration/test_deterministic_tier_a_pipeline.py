"""Integration tests verifying the deterministic pipeline against all Tier A fixtures.

Exit Criterion for Phase 2:
"Unit tests pass for all components. Pipeline produces correct verdicts on Tier A fixtures. No LLM required."
"""

import json
from pathlib import Path
import pytest
from risk_agent.models.schemas import ClaimType, SeverityVerdict
from risk_agent.pipeline import DeterministicPipeline
from risk_agent.policy.policy_engine import PolicyEngine

TIER_A_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "tier_a"


def load_all_tier_a_specs():
    cases_file = TIER_A_DIR / "cases.json"
    with open(cases_file, "r", encoding="utf-8") as f:
        cases_meta = json.load(f)

    specs = []
    for c in cases_meta:
        case_dir = TIER_A_DIR / c["directory"]
        spec_path = case_dir / "case.json"
        with open(spec_path, "r", encoding="utf-8") as sf:
            spec = json.load(sf)
        specs.append((case_dir, spec))
    return specs


ALL_SPECS = load_all_tier_a_specs()


@pytest.mark.parametrize("case_dir, spec", ALL_SPECS, ids=[s[1]["case_id"] for s in ALL_SPECS])
def test_deterministic_pipeline_on_tier_a_fixtures(case_dir: Path, spec: dict):
    """Verifies that the deterministic pipeline without any LLM achieves the exact ground-truth verdict."""
    pipeline = DeterministicPipeline()

    ground_truth = spec["ground_truth"]
    expected_verdict = ground_truth["expected_verdict"]
    expected_floor = ground_truth["risk_floor"]
    affected_api = ground_truth.get("affected_api")

    # Read upstream release notes if available
    release_notes_meta = spec.get("release_notes", {})
    notes_rel_path = release_notes_meta.get("file_path")
    raw_content = ""
    is_available = release_notes_meta.get("is_available", True)

    if notes_rel_path:
        notes_file = case_dir / notes_rel_path
        if notes_file.exists():
            with open(notes_file, "r", encoding="utf-8") as f:
                raw_content = f.read()

    # Determine claim type
    category = spec.get("category", "")
    claim_type = ClaimType.DEPRECATION if category == "DEPRECATION" else ClaimType.BREAKING

    # Find a verified quote from release notes if applicable
    quote_text = None
    if raw_content and is_available:
        if ground_truth.get("quote_verification_expected") is False:
            # Simulate a hallucinated quote that fails verification against the release notes
            quote_text = "Completely fabricated claim that does not exist in release notes at all"
        else:
            # Extract first non-heading sentence/bullet from release notes as quote
            for line in raw_content.splitlines():
                s_line = line.strip()
                if s_line.startswith("-") or ("Removed" in s_line or "Changed" in s_line or "deprecated" in s_line.lower()):
                    quote_text = s_line.lstrip("-* ").strip()
                    break

    # Execute deterministic pipeline
    report = pipeline.evaluate_fixture_case(
        case_dir=case_dir,
        raw_release_notes=raw_content,
        affected_api=affected_api,
        claim_type=claim_type,
        quoted_claim_text=quote_text,
        is_release_notes_available=is_available,
    )

    # For prompt injection test (Case 6), simulate an injected LLM suggesting NO_RISK_FOUND
    if spec.get("category") == "PROMPT_INJECTION":
        # Ensure that even if an untrusted component suggests NO_RISK_FOUND, the final verdict remains RISKY
        final_with_injected_suggestion = PolicyEngine.compute_final_verdict(
            risk_floor=report.risk_floor,
            llm_verdict=SeverityVerdict.NO_RISK_FOUND,
        )
        assert final_with_injected_suggestion == SeverityVerdict.RISKY, (
            "Prompt injection defense failed: Injected suggestion lowered the risk floor!"
        )

    # Assert ground-truth verdict match
    assert report.verdict.value == expected_verdict, (
        f"Verdict mismatch for {spec['case_id']} ({spec['name']}): "
        f"expected {expected_verdict}, got {report.verdict.value}. "
        f"Reasons: {report.reasons}"
    )
    assert report.risk_floor.value == expected_floor, (
        f"Risk floor mismatch for {spec['case_id']}: expected {expected_floor}, got {report.risk_floor.value}"
    )
