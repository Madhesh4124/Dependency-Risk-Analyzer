"""Evaluation pipelines for Dependency Upgrade Risk Agent (Phase 2 & Phase 3)."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from risk_agent.config import DEFAULT_CONFIG
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
from risk_agent.parser.diff_parser import ManifestDiffParser, determine_bump_type
from risk_agent.policy.policy_engine import PolicyEngine
from risk_agent.resolver.package_resolver import PackageResolver
from risk_agent.scanner.ast_scanner import ASTScanner
from risk_agent.security.injection_detector import InjectionDetector, InjectionResult
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
        package_name: Optional[str] = None,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        bump_type: Optional[VersionBumpType] = None,
    ) -> RiskReport:
        """Evaluates a repository snapshot against a dependency update deterministically."""
        repo_dir = case_dir / "repo" if (case_dir / "repo").exists() else case_dir
        req_file = repo_dir / "requirements.txt"
        manifest_content = ""
        if req_file.exists():
            with open(req_file, "r", encoding="utf-8") as f:
                manifest_content = f.read()

        pkgs = ManifestDiffParser.parse_requirements_content(manifest_content)
        pkg_name = package_name or (list(pkgs.keys())[0] if pkgs else "unknown")
        old_ver = old_version or pkgs.get(pkg_name, "1.0.0")
        new_ver = new_version or "2.0.0"

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

        if bump_type is None:
            bump_type = determine_bump_type(old_ver, new_ver)
            if bump_type == VersionBumpType.UNKNOWN:
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
            new_version=new_ver,
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
    """Full Phase 3-6 pipeline integrating security shield, LLM extraction, quote verification, AST scanning, and risk floor."""

    def __init__(
        self,
        extractor: Optional[LLMExtractor] = None,
        injection_detector: Optional[InjectionDetector] = None,
    ):
        self.extractor = extractor or LLMExtractor()
        self.injection_detector = injection_detector or InjectionDetector()
        self.quote_verifier = QuoteVerifier()
        self.ast_scanner = ASTScanner()

    def evaluate_case(
        self,
        case_dir: Path,
        raw_release_notes: str,
        package_name: Optional[str] = None,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        bump_type: Optional[VersionBumpType] = None,
        is_release_notes_available: bool = True,
        source_url: Optional[str] = None,
    ) -> RiskReport:
        """Evaluates a local directory fixture case."""
        repo_dir = case_dir / "repo" if (case_dir / "repo").exists() else case_dir
        req_file = repo_dir / "requirements.txt"
        manifest_content = ""
        if req_file.exists():
            with open(req_file, "r", encoding="utf-8") as f:
                manifest_content = f.read()

        from risk_agent.scanner.repo_fetcher import RepoSourceFetcher
        sources = RepoSourceFetcher.load_sources_from_local_dir(repo_dir)

        return self.evaluate_with_sources(
            sources=sources,
            raw_release_notes=raw_release_notes,
            manifest_content=manifest_content,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            bump_type=bump_type,
            is_release_notes_available=is_release_notes_available,
            source_url=source_url,
        )

    def evaluate_with_sources(
        self,
        sources: dict[str, str],
        raw_release_notes: str,
        manifest_content: str = "",
        package_name: Optional[str] = None,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        bump_type: Optional[VersionBumpType] = None,
        is_release_notes_available: bool = True,
        source_url: Optional[str] = None,
        documentation_url: Optional[str] = None,
        pr_title: str = "",
        pr_body: str = "",
        commit_messages: Optional[Sequence[str]] = None,
        injection_result: Optional[InjectionResult] = None,
    ) -> RiskReport:
        """Executes the full pipeline against in-memory repository source files."""
        if not package_name:
            pkgs = ManifestDiffParser.parse_requirements_content(manifest_content)
            package_name = list(pkgs.keys())[0] if pkgs else "unknown"
            if not old_version:
                old_version = pkgs.get(package_name, "1.0.0")

        if not new_version:
            new_version = "2.0.0"

        if isinstance(bump_type, str):
            try:
                bump_type = VersionBumpType(bump_type.lower())
            except Exception:
                bump_type = None

        if bump_type is None:
            bump_type = determine_bump_type(old_version, new_version)
            if bump_type == VersionBumpType.UNKNOWN:
                bump_type = VersionBumpType.MAJOR

        # Step 1.5: Ingress Security Scan (Google Cloud Model Armor + Local Heuristic Tripwires)
        active_injection = injection_result
        if active_injection is None:
            active_injection = self.injection_detector.scan_pr(
                pr_title=pr_title,
                pr_body=pr_body,
                release_notes=raw_release_notes,
                commit_messages=commit_messages,
            )

        llm_input_notes = (
            self.injection_detector.quarantine_untrusted_text(
                raw_release_notes,
                injection_result=active_injection,
            )
            if raw_release_notes
            else ""
        )

        # Step 2: Resolve package to module import names
        resolution = PackageResolver.resolve(package_name)

        # Step 3: LLM Extraction (receives sanitized/quarantined release notes)
        llm_verdict: Optional[SeverityVerdict] = None
        extracted_claims: List[ExtractedClaim] = []
        model_id = self.extractor.model_name
        prompt_version = self.extractor.prompt_version
        triggered_filters: List[str] = list(getattr(active_injection, "triggered_filters", []) or [])
        injection_detected = bool(active_injection and active_injection.detected)
        injection_pattern = (
            active_injection.pattern_type.value
            if (active_injection and active_injection.pattern_type)
            else None
        )
        injection_engine = active_injection.engine if injection_detected else None

        ma_statuses: List[str] = []
        ma_errors: List[str] = []
        init_ma_status = getattr(active_injection, "model_armor_status", None)
        if init_ma_status and init_ma_status != "disabled":
            ma_statuses.append(init_ma_status)
        if getattr(active_injection, "model_armor_error", None):
            ma_errors.append(f"ingress: {active_injection.model_armor_error}")

        if is_release_notes_available and raw_release_notes.strip() and llm_input_notes.strip():
            extraction_res: LLMExtractionResult = self.extractor.extract_claims(
                package_name=package_name,
                old_version=old_version,
                new_version=new_version,
                release_notes=llm_input_notes,
            )
            extracted_claims = extraction_res.claims
            llm_verdict = extraction_res.overall_risk
            model_id = extraction_res.model_id
            prompt_version = extraction_res.prompt_version

            # Step 3.5: Egress Model Response Security Check (Model Armor SanitizeModelResponse + Leak Guard)
            if extraction_res.status == "success":
                serialized_response = "\n".join(
                    [extraction_res.summary or ""]
                    + [
                        f"{c.affected_api or ''}: {c.description or ''} {c.quoted_text or ''}"
                        for c in extracted_claims
                    ]
                ).strip()
                should_scan_egress = bool(
                    serialized_response
                    and (
                        (
                            self.injection_detector.enable_model_armor
                            and self.injection_detector.scan_model_response_enabled
                        )
                        or any(
                            tok in serialized_response
                            for tok in ("BEGIN ", "ghp_", "ghs_", "AIza", "GITHUB_TOKEN=", "AWS_SECRET_ACCESS_KEY")
                        )
                    )
                )
                if should_scan_egress:
                    egress_res = self.injection_detector.scan_model_response(
                        response_text=serialized_response,
                        user_prompt=llm_input_notes[:2000],
                    )
                    if egress_res.model_armor_status and egress_res.model_armor_status != "disabled":
                        ma_statuses.append(egress_res.model_armor_status)
                    if egress_res.model_armor_error:
                        ma_errors.append(f"egress: {egress_res.model_armor_error}")
                    if egress_res.detected:
                        injection_detected = True
                        if not injection_pattern and egress_res.pattern_type:
                            injection_pattern = egress_res.pattern_type.value
                        if not injection_engine:
                            injection_engine = egress_res.engine
                        elif (
                            egress_res.engine
                            and egress_res.engine != "none"
                            and egress_res.engine not in injection_engine
                        ):
                            injection_engine = f"{injection_engine}+{egress_res.engine}"
                        for flt in egress_res.triggered_filters:
                            if flt not in triggered_filters:
                                triggered_filters.append(flt)

        # Step 4: Quote Verification (strictly verified against unmodified raw_release_notes)
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

        # Step 5: AST Scanning for verified affected APIs in sources
        usages: List[UsageMatch] = []
        scanned_symbols = set()
        for claim in verified_claims:
            if claim.affected_api and claim.affected_api not in scanned_symbols:
                scanned_symbols.add(claim.affected_api)
                found_usages = self.ast_scanner.scan_source_dict(
                    sources=sources,
                    target_modules=resolution.import_module_names,
                    affected_api=claim.affected_api,
                )
                usages.extend(found_usages)

        # Resolve aggregate Model Armor inspection state & fail-closed enforcement
        overall_ma_error = "; ".join(ma_errors) if ma_errors else None
        if "matched" in ma_statuses:
            overall_ma_status = "matched"
        elif "error" in ma_statuses:
            overall_ma_status = "error"
        elif "clean" in ma_statuses:
            overall_ma_status = "clean"
        else:
            overall_ma_status = init_ma_status or (
                "clean" if self.injection_detector.enable_model_armor else "disabled"
            )

        ma_fail_closed = bool(
            self.injection_detector.fail_closed and overall_ma_status == "error"
        )

        # Step 6: Evaluate Deterministic Floor
        floor, reasons = PolicyEngine.evaluate_risk_floor(
            bump_type=bump_type,
            release_notes_available=is_release_notes_available,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            usages=usages,
            injection_detected=injection_detected,
            model_armor_error=ma_fail_closed,
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
            documentation_url=documentation_url,
            model_id=model_id,
            prompt_version=prompt_version,
            injection_detected=injection_detected,
            injection_pattern=injection_pattern,
            injection_engine=injection_engine,
            model_armor_status=overall_ma_status,
            model_armor_error=overall_ma_error,
            model_armor_triggered_filters=triggered_filters,
        )

    def evaluate_upgrade(
        self,
        package_name: str,
        old_version: str,
        new_version: str,
        bump_type: Optional[Any] = None,
        manifest_diff: str = "",
        raw_release_notes: str = "",
        repo_snippets: Optional[dict[str, str]] = None,
        source_url: Optional[str] = None,
        **kwargs,
    ) -> RiskReport:
        """Alias for evaluate_with_sources providing complete backward and forward compatibility."""
        bump = bump_type
        if isinstance(bump, str):
            try:
                bump = VersionBumpType(bump.lower())
            except Exception:
                bump = None
        return self.evaluate_with_sources(
            sources=repo_snippets or {},
            raw_release_notes=raw_release_notes,
            manifest_content=manifest_diff,
            package_name=package_name,
            old_version=old_version,
            new_version=new_version,
            bump_type=bump,
            source_url=source_url or f"https://pypi.org/project/{package_name}",
            pr_title=kwargs.get("pr_title", ""),
            pr_body=kwargs.get("pr_body", ""),
            commit_messages=kwargs.get("commit_messages"),
            injection_result=kwargs.get("injection_result"),
        )
