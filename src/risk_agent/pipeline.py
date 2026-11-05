"""Evaluation pipelines for Dependency Upgrade Risk Agent (Phase 2 & Phase 3)."""

from pathlib import Path
from typing import List, Optional

from risk_agent.extraction.extractor import LLMExtractor
from risk_agent.extraction.schemas import LLMExtractionResult
from risk_agent.models.schemas import (
    ClaimType,
    ExtractedClaim,
    ReleaseNoteSnapshot,
    RiskReport,
    SeverityVerdict,
    UsageMatch,
    VersionBumpType,
)
from risk_agent.parser.diff_parser import ManifestDiffParser
from risk_agent.policy.policy_engine import PolicyEngine
from risk_agent.resolver.package_resolver import PackageResolver
from risk_agent.scanner.ast_scanner import ASTScanner
from risk_agent.verifier.quote_verifier import QuoteVerifier


class DeterministicPipeline:
    """Executes the complete deterministic evaluation pipeline without any LLM (Phase 2 baseline)."""

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

        pkgs = ManifestDiffParser.parse_requirements_content(manifest_content)
        pkg_name = list(pkgs.keys())[0] if pkgs else "unknown"
        old_ver = pkgs.get(pkg_name, "1.0.0")

        resolution = PackageResolver.resolve(pkg_name)

        verified_claims: List[ExtractedClaim] = []
        unverified_claims: List[ExtractedClaim] = []

        if quoted_claim_text and is_release_notes_available and raw_release_notes:
            q_res = self.quote_verifier.verify_quote(quoted_claim_text, raw_release_notes)
            claim = ExtractedClaim(
                claim_id="claim-1",
                claim_type=claim_type,
                affected_api=affected_api,
                quoted_text=quoted_claim_text,
                is_verified=q_res.is_verified,
            )
            if q_res.is_verified:
                verified_claims.append(claim)
            else:
                unverified_claims.append(claim)

        usages = []
        if affected_api:
            usages = self.ast_scanner.scan_directory(
                root_dir=repo_dir,
                target_modules=resolution.import_module_names,
                affected_api=affected_api,
            )

        bump_type = VersionBumpType.MAJOR
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


class RiskAgentPipeline:
    """Full Phase 3 pipeline integrating LLM extraction, quote verification, AST scanning, and risk floor."""

    def __init__(self, extractor: Optional[LLMExtractor] = None):
        self.extractor = extractor or LLMExtractor()
        self.quote_verifier = QuoteVerifier()
        self.ast_scanner = ASTScanner()

    def evaluate_case(
        self,
        case_dir: Path,
        raw_release_notes: str,
        package_name: Optional[str] = None,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        bump_type: VersionBumpType = VersionBumpType.MAJOR,
        is_release_notes_available: bool = True,
        source_url: Optional[str] = None,
    ) -> RiskReport:
        """Executes the full pipeline:

        1. Parse repository manifest
        2. Resolve PyPI distribution to module import names
        3. Extract candidate claims via Vertex AI LLM
        4. Verify quotations against raw release notes
        5. AST-scan repository source for verified affected APIs
        6. Compute deterministic risk floor
        7. Compute final verdict = max(floor, llm_suggestion)
        8. Return comprehensive RiskReport
        """
        repo_dir = case_dir / "repo" if (case_dir / "repo").exists() else case_dir
        req_file = repo_dir / "requirements.txt"
        manifest_content = ""
        if req_file.exists():
            with open(req_file, "r", encoding="utf-8") as f:
                manifest_content = f.read()

        if not package_name:
            pkgs = ManifestDiffParser.parse_requirements_content(manifest_content)
            package_name = list(pkgs.keys())[0] if pkgs else "unknown"
            if not old_version:
                old_version = pkgs.get(package_name, "1.0.0")

        if not new_version:
            new_version = "2.0.0"

        # Step 2: Resolve package to module import names
        resolution = PackageResolver.resolve(package_name)

        # Step 3: LLM Extraction
        llm_verdict: Optional[SeverityVerdict] = None
        extracted_claims: List[ExtractedClaim] = []
        model_id = self.extractor.model_name
        prompt_version = self.extractor.prompt_version

        if is_release_notes_available and raw_release_notes.strip():
            extraction_res: LLMExtractionResult = self.extractor.extract_claims(
                package_name=package_name,
                old_version=old_version,
                new_version=new_version,
                release_notes=raw_release_notes,
            )
            extracted_claims = extraction_res.claims
            llm_verdict = extraction_res.overall_risk
            model_id = extraction_res.model_id
            prompt_version = extraction_res.prompt_version

        # Step 4: Quote Verification
        verified_claims: List[ExtractedClaim] = []
        unverified_claims: List[ExtractedClaim] = []

        for claim in extracted_claims:
            if is_release_notes_available and raw_release_notes.strip():
                q_res = self.quote_verifier.verify_quote(claim.quoted_text, raw_release_notes)
                claim.is_verified = q_res.is_verified
                if q_res.is_verified:
                    verified_claims.append(claim)
                else:
                    unverified_claims.append(claim)
            else:
                claim.is_verified = False
                unverified_claims.append(claim)

        # Step 5: AST Scanning for verified affected APIs
        usages: List[UsageMatch] = []
        scanned_symbols = set()
        for claim in verified_claims:
            if claim.affected_api and claim.affected_api not in scanned_symbols:
                scanned_symbols.add(claim.affected_api)
                found_usages = self.ast_scanner.scan_directory(
                    root_dir=repo_dir,
                    target_modules=resolution.import_module_names,
                    affected_api=claim.affected_api,
                )
                usages.extend(found_usages)

        # Step 6: Evaluate Deterministic Floor
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=bump_type,
            release_notes_available=is_release_notes_available,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            usages=usages,
        )

        # Step 7: Combine with LLM verdict (CANNOT LOWER FLOOR)
        final_verdict = PolicyEngine.compute_final_verdict(
            risk_floor=floor,
            llm_verdict=llm_verdict,
        )

        if llm_verdict and PolicyEngine.compare_verdicts(llm_verdict, floor) > 0:
            reasons.append(
                f"Verdict elevated to {llm_verdict.value} by LLM recommendation ({model_id})."
            )

        return RiskReport(
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            bump_type=bump_type,
            verdict=final_verdict,
            risk_floor=floor,
            llm_verdict=llm_verdict,
            reasons=reasons,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            potential_usages=usages,
            release_notes_available=is_release_notes_available,
            source_url=source_url,
            model_id=model_id,
            prompt_version=prompt_version,
        )
