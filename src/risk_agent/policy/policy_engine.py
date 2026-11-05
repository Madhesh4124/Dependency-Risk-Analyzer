"""Deterministic verdict policy engine and risk floor rules."""

from typing import List, Optional, Tuple
from risk_agent.models.schemas import (
    ConfidenceTier,
    ExtractedClaim,
    ClaimType,
    RiskReport,
    SeverityVerdict,
    UsageMatch,
    VersionBumpType,
)

SEVERITY_ORDER = {
    SeverityVerdict.NO_RISK_FOUND: 0,
    SeverityVerdict.REVIEW: 1,
    SeverityVerdict.RISKY: 2,
}


def escalate(v1: SeverityVerdict, v2: SeverityVerdict) -> SeverityVerdict:
    """Returns the higher of two verdicts on the ordered severity scale."""
    return v1 if SEVERITY_ORDER[v1] >= SEVERITY_ORDER[v2] else v2


class PolicyEngine:
    """Computes deterministic risk floors and ensures verdict cannot drop below evidence."""

    @classmethod
    def evaluate_risk_floor(
        cls,
        bump_type: VersionBumpType,
        release_notes_available: bool,
        verified_claims: List[ExtractedClaim],
        unverified_claims: List[ExtractedClaim],
        usages: List[UsageMatch],
    ) -> Tuple[SeverityVerdict, List[str]]:
        """Evaluates the strict deterministic risk floor based on physical evidence."""
        reasons: List[str] = []
        floor = SeverityVerdict.NO_RISK_FOUND

        # Floor Rule 1: Missing or unavailable release notes
        if not release_notes_available:
            floor = escalate(floor, SeverityVerdict.REVIEW)
            reasons.append("Upstream release notes are missing, empty, or could not be retrieved")

        # Floor Rule 2: Major version bump with missing/unverified documentation (Decision D-01 Option C)
        if bump_type == VersionBumpType.MAJOR and not release_notes_available:
            floor = escalate(floor, SeverityVerdict.REVIEW)
            reasons.append("Major version bump without verifiable release documentation")

        # Separate verified claims by type
        verified_breaking = [c for c in verified_claims if c.claim_type == ClaimType.BREAKING]
        verified_deprecations = [c for c in verified_claims if c.claim_type == ClaimType.DEPRECATION]

        # Floor Rule 3: Breaking change with HIGH confidence code usage
        high_usages = [u for u in usages if u.confidence_tier == ConfidenceTier.HIGH]
        medium_usages = [u for u in usages if u.confidence_tier == ConfidenceTier.MEDIUM]
        low_usages = [u for u in usages if u.confidence_tier == ConfidenceTier.LOW]

        if verified_breaking and high_usages:
            floor = escalate(floor, SeverityVerdict.RISKY)
            reasons.append(
                f"Verified breaking change affects {len(high_usages)} direct code usage(s): "
                f"{', '.join(u.matched_symbol for u in high_usages[:3])}"
            )

        # Floor Rule 4: Breaking change with MEDIUM or LOW confidence usage
        elif verified_breaking and (medium_usages or low_usages):
            floor = escalate(floor, SeverityVerdict.REVIEW)
            reasons.append(
                "Verified breaking change found; repository contains potential matches with "
                "uncertain type resolution (avoids false alarm on generic method names)"
            )

        # Floor Rule 5: Deprecations exercised by code
        if verified_deprecations and (high_usages or medium_usages):
            floor = escalate(floor, SeverityVerdict.REVIEW)
            reasons.append(
                f"Active deprecation exercised by repository code: "
                f"{', '.join(u.matched_symbol for u in (high_usages + medium_usages)[:3])}"
            )

        # Floor Rule 6: Unverified claims only
        if unverified_claims and not verified_claims:
            floor = escalate(floor, SeverityVerdict.REVIEW)
            reasons.append(
                f"Contains {len(unverified_claims)} release claim(s) that could not be verified in source notes"
            )

        # Default clean pass reason
        if floor == SeverityVerdict.NO_RISK_FOUND:
            reasons.append("Sufficient release documentation verified; no breaking usages detected in repository")

        return floor, reasons

    @classmethod
    def compute_final_verdict(
        cls,
        risk_floor: SeverityVerdict,
        llm_verdict: Optional[SeverityVerdict] = None,
    ) -> SeverityVerdict:
        """Computes the final verdict.

        Rule: LLM can escalate the verdict higher, but can NEVER lower the risk floor.
        Final = max(risk_floor, llm_verdict)
        """
        if llm_verdict is None:
            return risk_floor
        return escalate(risk_floor, llm_verdict)

