"""End-to-end deterministic evaluation pipeline for Dependency Upgrade Risk Agent."""

from pathlib import Path
from typing import List, Optional
from risk_agent.models.schemas import (
    ClaimType,
    ExtractedClaim,
    ReleaseNoteSnapshot,
    RiskReport,
    SeverityVerdict,
    VersionBumpType,
)
from risk_agent.parser.diff_parser import ManifestDiffParser
from risk_agent.resolver.package_resolver import PackageResolver
from risk_agent.verifier.quote_verifier import QuoteVerifier
from risk_agent.scanner.ast_scanner import ASTScanner
from risk_agent.policy.policy_engine import PolicyEngine


class DeterministicPipeline:
    """Executes the complete deterministic evaluation pipeline without any LLM."""

    def __init__(self):
        self.quote_verifier = QuoteVerifier()
        self.ast_scanner = ASTScanner()

    def evaluate_fixture_case(
        self,
        case_dir: Path,
        raw_release_notes: str,
        affected_api: Optional[str] = None,
        claim_type: ClaimType = ClaimType.BREAKING,
        quoted_claim_text: Optional[str] = None,
        is_release_notes_available: bool = True,
    ) -> RiskReport:
        """Evaluates a repository snapshot against a dependency update deterministically."""
        repo_dir = case_dir / "repo"
        req_file = repo_dir / "requirements.txt"
        manifest_content = ""
        if req_file.exists():
            with open(req_file, "r", encoding="utf-8") as f:
                manifest_content = f.read()

        # 1. Parse manifest diff (simulate bump from req_file or spec)
        # Parse package name from requirements.txt
        pkgs = ManifestDiffParser.parse_requirements_content(manifest_content)
        pkg_name = list(pkgs.keys())[0] if pkgs else "unknown"
        old_ver = pkgs.get(pkg_name, "1.0.0")

        # 2. Resolve package to module import names
        resolution = PackageResolver.resolve(pkg_name)

        # 3. Verify quote if provided
        verified_claims: List[ExtractedClaim] = []
        unverified_claims: List[ExtractedClaim] = []

        if quoted_claim_text and is_release_notes_available and raw_release_notes:
            q_res = self.quote_verifier.verify_quote(quoted_claim_text, raw_release_notes)
            claim = ExtractedClaim(
                claim_id="claim-1",
                claim_type=claim_type,
                affected_api=affected_api,
                quoted_text=quoted_claim_text,
            )
            if q_res.is_verified:
                verified_claims.append(claim)
            else:
                unverified_claims.append(claim)

        # 4. AST scan for potential usages
        usages = []
        if affected_api:
            usages = self.ast_scanner.scan_directory(
                root_dir=repo_dir,
                target_modules=resolution.import_module_names,
                affected_api=affected_api,
            )

        # 5. Evaluate deterministic risk floor
        bump_type = VersionBumpType.MAJOR  # conservative default for fixtures
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=bump_type,
            release_notes_available=is_release_notes_available,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            usages=usages,
        )

        final_verdict = PolicyEngine.compute_final_verdict(risk_floor=floor, llm_verdict=None)

        return RiskReport(
            package_name=pkg_name,
            old_version=old_ver,
            new_version="2.0.0",
            bump_type=bump_type,
            verdict=final_verdict,
            risk_floor=floor,
            reasons=reasons,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            potential_usages=usages,
            release_notes_available=is_release_notes_available,
        )

