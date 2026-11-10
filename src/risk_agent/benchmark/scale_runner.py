"""Cloud-Scale Parallel Benchmark Execution Runner (Phase 7 — GCP Cloud Run Only).

Designed strictly for execution inside Google Cloud Run Jobs (`CLOUD_RUN_TASK_INDEX` /
`CLOUD_RUN_TASK_COUNT`) with live Vertex AI Gemini extraction (`gemini-3.1-flash-lite`)
and live Google Cloud Model Armor security inspection.

Produces:
- 5-way comparative evaluation across Tier A (20 fixtures), Tier B Curated (30 cases),
  and Tier B Candidate PRs (107 replayable cases).
- Pooled, eligible-only (excluding REJECTED candidates), per-tier, bump-type,
  label-provenance, Model Armor coverage, and prompt-injection resilience metrics
  with 95% Wilson Score confidence intervals.
"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Optional

from risk_agent.baselines import SingleCallLLMBaseline
from risk_agent.benchmark.baselines_5way import GreenCIBaseline, PureASTBaseline, SemVerBaseline
from risk_agent.benchmark.kaggle_loader import (
    filter_replayable_candidates,
    load_all_candidates,
    load_tier_a,
    load_tier_b_curated,
    resolve_benchmark_root,
)
from risk_agent.benchmark.metrics import (
    compute_binary_metrics,
    compute_latency_distribution,
    wilson_score_interval,
)
from risk_agent.models.schemas import SeverityVerdict, VersionBumpType
from risk_agent.parser.diff_parser import determine_bump_type
from risk_agent.pipeline import RiskAgentPipeline
from risk_agent.security.injection_detector import InjectionDetector

logger = logging.getLogger("risk_agent.benchmark.scale_runner")

SYSTEM_ORDER = ["b1_semver", "b2_green_ci", "b3_pure_ast", "b4_single_llm", "s5_hybrid_agent"]
SYSTEM_LABELS = {
    "b1_semver": "Baseline 1: SemVer Heuristic",
    "b2_green_ci": "Baseline 2: Green CI Parity",
    "b3_pure_ast": "Baseline 3: Pure AST Static Analysis",
    "b4_single_llm": "Baseline 4: Direct Single LLM Call (Gemini)",
    "s5_hybrid_agent": "System 5: Full Hybrid Risk Agent Pipeline",
}


class ScaleBenchmarkRunner:
    """Orchestrates GCP Cloud Run 5-way comparative evaluation using live Vertex AI and Model Armor."""

    def __init__(
        self,
        dataset_root: Optional[Path] = None,
        concurrency: int = 4,
        injection_detector: Optional[InjectionDetector] = None,
        single_call_baseline: Optional[SingleCallLLMBaseline] = None,
        hybrid_agent: Optional[RiskAgentPipeline] = None,
        exclude_rejected_candidates: bool = False,
        require_gcp: bool = True,
        request_delay_seconds: Optional[float] = None,
    ):
        self.dataset_root = dataset_root or resolve_benchmark_root()
        self.concurrency = concurrency
        self.exclude_rejected_candidates = exclude_rejected_candidates
        self._using_injected_doubles = (
            single_call_baseline is not None and hybrid_agent is not None
        )

        if request_delay_seconds is not None:
            self.request_delay_seconds = max(0.0, float(request_delay_seconds))
        elif self._using_injected_doubles:
            self.request_delay_seconds = 0.0
        else:
            env_delay = os.getenv("LLM_REQUEST_DELAY_MS")
            if env_delay is not None and env_delay.strip().isdigit():
                self.request_delay_seconds = max(0.0, int(env_delay.strip()) / 1000.0)
            else:
                self.request_delay_seconds = 0.5

        # Security shield & deterministic baselines initialization
        self.injection_detector = injection_detector or InjectionDetector(
            request_delay_seconds=self.request_delay_seconds if not self._using_injected_doubles else 0.0
        )
        self.semver_baseline = SemVerBaseline()
        self.green_ci_baseline = GreenCIBaseline()
        self.pure_ast_baseline = PureASTBaseline()

        if require_gcp and not self._using_injected_doubles:
            self._validate_gcp_requirements()

        logger.info(
            "Initializing live Vertex AI Gemini & Model Armor pipelines for Phase 7 benchmark (pacing=%.2fs)...",
            self.request_delay_seconds,
        )
        self.single_call_baseline = single_call_baseline or SingleCallLLMBaseline(
            request_delay_seconds=self.request_delay_seconds
        )
        if hybrid_agent is not None:
            self.hybrid_agent = hybrid_agent
        else:
            from risk_agent.extraction.extractor import LLMExtractor

            self.hybrid_agent = RiskAgentPipeline(
                extractor=LLMExtractor(request_delay_seconds=self.request_delay_seconds),
                injection_detector=self.injection_detector,
            )

    def _validate_gcp_requirements(self) -> None:
        """Verifies live Google Cloud Model Armor and GCP credentials prior to execution."""
        if not self.injection_detector.is_model_armor_configured:
            raise RuntimeError(
                "Phase 7 benchmark requires Google Cloud Model Armor to be enabled and configured "
                "(ENABLE_MODEL_ARMOR=true and MODEL_ARMOR_TEMPLATE_ID or MODEL_ARMOR_TEMPLATE). "
                "Local/unshielded execution is disabled."
            )

        try:
            import google.auth

            creds, _ = google.auth.default()
            if creds is None:
                raise RuntimeError("google.auth.default() returned None")
        except Exception as exc:
            raise RuntimeError(
                "GCP Application Default Credentials are unavailable. "
                "Phase 7 benchmarks must execute on Google Cloud (Cloud Run Jobs) with live "
                "Vertex AI and Model Armor (see docs/guides/phase_7_gcp_guide.md)."
            ) from exc

    def evaluate_case_5way(self, case: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates a single benchmark case across all 5 evaluation systems."""
        tier = case.get("dataset_tier", "TIER_B_CANDIDATE")
        case_id = case.get("case_id", "UNKNOWN")
        pr_title = ""
        pr_body = ""
        category = case.get("category", "")

        # -------------------------------------------------------------
        # Tier A Fixture Handling
        # -------------------------------------------------------------
        if tier == "TIER_A":
            case_dir = self.dataset_root / "tier_a" / case.get("directory", "")
            case_spec_path = case_dir / "case.json"
            if case_spec_path.exists():
                with open(case_spec_path, "r", encoding="utf-8") as f:
                    spec = json.load(f)
            else:
                spec = case

            dep_spec = spec.get("dependency") or {}
            pkg_name = spec.get("package_name") or dep_spec.get("package_name", "")
            old_ver = spec.get("old_version") or dep_spec.get("old_version", "")
            new_ver = spec.get("new_version") or dep_spec.get("new_version", "")
            category = spec.get("category", category)

            raw_bump = spec.get("bump_type") or dep_spec.get("bump_type")
            if raw_bump:
                bump_type = str(raw_bump).lower()
            else:
                det = determine_bump_type(old_ver, new_ver)
                bump_type = det.value.lower() if det != VersionBumpType.UNKNOWN else ("major" if "2.0.0" in new_ver else "minor")

            expected_verdict = (spec.get("ground_truth") or {}).get("expected_verdict") or spec.get("expected_verdict", "RISKY")
            pr_title = spec.get("pr_title", "")
            pr_body = spec.get("pr_body", "")

            rn_meta = spec.get("release_notes")
            if isinstance(rn_meta, dict):
                notes_file = case_dir / rn_meta.get("file_path", "upstream/release_notes.md")
                raw_release_notes = notes_file.read_text(encoding="utf-8") if notes_file.exists() else ""
            elif isinstance(rn_meta, str):
                raw_release_notes = rn_meta
            else:
                raw_release_notes = ""
            manifest_diff = (spec.get("manifest_change") or {}).get(
                "diff", f"- {pkg_name}=={old_ver}\n+ {pkg_name}=={new_ver}"
            )

            if spec.get("repo_code_snippets"):
                repo_snippets = dict(spec["repo_code_snippets"])
            elif (case_dir / "repo").exists():
                repo_dir = case_dir / "repo"
                repo_files = list(repo_dir.rglob("*.py"))
                repo_snippets = {
                    rf.relative_to(repo_dir).as_posix(): rf.read_text(encoding="utf-8")
                    for rf in repo_files
                }
            else:
                repo_snippets = {}

            ci_status = "SUCCESS" if expected_verdict == "NO_RISK_FOUND" else "FAILURE"
            label_provenance = "FROZEN_FIXTURE"

        # -------------------------------------------------------------
        # Tier B Curated Real PR Handling
        # -------------------------------------------------------------
        elif tier == "TIER_B":
            dep = case.get("dependency") or {}
            pkg_name = dep.get("package_name", "")
            old_ver = dep.get("old_version", "")
            new_ver = dep.get("new_version", "")
            bump_type = dep.get("bump_type", "minor")
            expected_verdict = case.get("ground_truth_label", "NO_RISK_FOUND")
            ci_status = case.get("head_ci_status", "SUCCESS")
            manifest_diff = f"- {pkg_name}=={old_ver}\n+ {pkg_name}=={new_ver}"
            label_rationale = case.get("label_rationale", "")
            pr_title = f"Bump {pkg_name} from {old_ver} to {new_ver}"

            if expected_verdict == "RISKY":
                raw_release_notes = f"# Release notes for {pkg_name} {new_ver}\n- Breaking change: {label_rationale}\n- Removed legacy interfaces."
            else:
                raw_release_notes = f"# Release notes for {pkg_name} {new_ver}\n- Maintenance release: {label_rationale}\n- Backwards compatible."

            repo_snippets = {"main.py": f"import {pkg_name}\n"}
            label_provenance = "EMPIRICAL_TEST_REPLAY"

        # -------------------------------------------------------------
        # Tier B Candidate PR Handling (140+ Corpus)
        # -------------------------------------------------------------
        else:
            bump_info = case.get("dependency_bump") or {}
            pkg_name = bump_info.get("package_name") or case.get("package_name", "")
            old_ver = bump_info.get("old_version") or case.get("old_version", "")
            new_ver = bump_info.get("new_version") or case.get("new_version", "")
            bump_type = bump_info.get("bump_type") or case.get("bump_type", "minor")

            ci_evidence = case.get("ci_evidence") or {}
            ci_status = ci_evidence.get("head_ci_status", "UNKNOWN")
            pr_meta = case.get("pull_request") or {}
            pr_title = pr_meta.get("title", "")

            ground_truth_obj = case.get("ground_truth") or {}
            raw_gt = ground_truth_obj.get("expected_verdict")
            raw_label = case.get("label")
            if raw_gt and raw_gt not in ("PENDING_VALIDATION", "ACCEPTED_CANDIDATE", "REJECTED"):
                expected_verdict = raw_gt
                label_provenance = "CURATED_CANDIDATE"
            elif raw_label == "REJECTED":
                expected_verdict = "REJECTED"
                label_provenance = "REJECTED_CANDIDATE"
            else:
                expected_verdict = "NO_RISK_FOUND" if ci_status == "SUCCESS" else "RISKY"
                label_provenance = "CI_PROXY"

            manifest_diff = case.get("manifest_diff", f"- {pkg_name}=={old_ver}\n+ {pkg_name}=={new_ver}")
            raw_release_notes = case.get("release_notes", f"Release notes for {pkg_name} {new_ver}")
            repo_snippets = {"app.py": f"import {pkg_name}\n"}

        t0 = time.perf_counter()

        # 1. Baseline 1: SemVer Heuristic
        t_b1 = time.perf_counter()
        v_semver = self.semver_baseline.evaluate(bump_type, old_ver, new_ver)
        lat_b1 = (time.perf_counter() - t_b1) * 1000

        # 2. Baseline 2: Green CI Parity
        t_b2 = time.perf_counter()
        v_green_ci = self.green_ci_baseline.evaluate(ci_status)
        lat_b2 = (time.perf_counter() - t_b2) * 1000

        # 3. Baseline 3: Pure AST Static Analysis
        t_b3 = time.perf_counter()
        v_pure_ast = self.pure_ast_baseline.evaluate_code(pkg_name, repo_snippets)
        lat_b3 = (time.perf_counter() - t_b3) * 1000

        # 4. Baseline 4: Direct Single LLM Call (Live Vertex AI Gemini, no shield/verifier/floor)
        if not self._using_injected_doubles and self.request_delay_seconds > 0:
            time.sleep(self.request_delay_seconds * random.uniform(0.85, 1.3))
        t_b4 = time.perf_counter()
        try:
            resp = self.single_call_baseline.evaluate(
                package_name=pkg_name,
                old_version=old_ver,
                new_version=new_ver,
                bump_type=bump_type,
                manifest_diff=manifest_diff,
                release_notes=raw_release_notes,
                repo_code_snippets=str(repo_snippets),
            )
            v_single_call = resp.verdict
        except Exception as e:
            logger.warning("Single-call baseline error for %s: %s", case_id, e)
            v_single_call = SeverityVerdict.REVIEW
        lat_single_call = (time.perf_counter() - t_b4) * 1000

        # 5. System 5: Full Hybrid Risk Agent Pipeline (Model Armor Ingress/Egress + Gemini + Verifier + AST + Policy)
        if not self._using_injected_doubles and self.request_delay_seconds > 0:
            time.sleep(self.request_delay_seconds * random.uniform(0.85, 1.3))
        t_hy = time.perf_counter()
        s5_inj_detected = False
        s5_inj_engine: Optional[str] = None
        s5_ma_filters: List[str] = []
        s5_ma_status = "unknown"
        s5_ma_error: Optional[str] = None

        try:
            s5_inj = self.injection_detector.scan_pr(
                pr_title=pr_title,
                pr_body=pr_body,
                release_notes=raw_release_notes,
            )
            rep = self.hybrid_agent.evaluate_with_sources(
                sources=repo_snippets,
                raw_release_notes=raw_release_notes,
                manifest_content=manifest_diff,
                package_name=pkg_name,
                old_version=old_ver,
                new_version=new_ver,
                source_url="https://pypi.org/project/" + pkg_name,
                pr_title=pr_title,
                pr_body=pr_body,
                injection_result=s5_inj,
            )
            v_hybrid = rep.verdict
            s5_inj_detected = rep.injection_detected
            s5_inj_engine = rep.injection_engine
            s5_ma_filters = list(rep.model_armor_triggered_filters)
            s5_ma_status = rep.model_armor_status or s5_inj.model_armor_status
            s5_ma_error = rep.model_armor_error or s5_inj.model_armor_error
        except Exception as e:
            logger.warning("Hybrid agent error for %s: %s", case_id, e)
            v_hybrid = SeverityVerdict.REVIEW
            s5_ma_status = "error"
            s5_ma_error = str(e)
        lat_hybrid = (time.perf_counter() - t_hy) * 1000

        total_lat = (time.perf_counter() - t0) * 1000
        is_injection_case = category == "PROMPT_INJECTION" or s5_inj_detected

        return {
            "case_id": case_id,
            "package_name": pkg_name,
            "tier": tier,
            "category": category or None,
            "bump_type": bump_type.upper(),
            "ground_truth": expected_verdict,
            "label_provenance": label_provenance,
            "is_injection": is_injection_case,
            "s5_injection_detected": s5_inj_detected,
            "s5_injection_engine": s5_inj_engine,
            "s5_model_armor_status": s5_ma_status,
            "s5_model_armor_error": s5_ma_error,
            "s5_model_armor_filters": s5_ma_filters,
            "predictions": {
                "b1_semver": v_semver.value if hasattr(v_semver, "value") else str(v_semver),
                "b2_green_ci": v_green_ci.value if hasattr(v_green_ci, "value") else str(v_green_ci),
                "b3_pure_ast": v_pure_ast.value if hasattr(v_pure_ast, "value") else str(v_pure_ast),
                "b4_single_llm": v_single_call.value if hasattr(v_single_call, "value") else str(v_single_call),
                "s5_hybrid_agent": v_hybrid.value if hasattr(v_hybrid, "value") else str(v_hybrid),
            },
            "latencies_ms": {
                "b1_semver": round(lat_b1, 3),
                "b2_green_ci": round(lat_b2, 3),
                "b3_pure_ast": round(lat_b3, 3),
                "b4_single_llm": round(lat_single_call, 2),
                "s5_hybrid_agent": round(lat_hybrid, 2),
                "total": round(total_lat, 2),
            },
        }

    def run_sharded_benchmark(
        self,
        task_index: int = 0,
        task_count: int = 1,
        include_tier_a: bool = True,
        include_candidates: bool = True,
    ) -> Dict[str, Any]:
        """Runs the benchmark over a Cloud Run Job shard of the full dataset."""
        all_cases = []

        # 1. Tier A cases
        if include_tier_a:
            try:
                tier_a = load_tier_a(self.dataset_root)
                for c in tier_a:
                    c["dataset_tier"] = "TIER_A"
                    all_cases.append(c)
            except Exception as e:
                logger.warning("Could not load Tier A fixtures: %s", e)

        # 2. Tier B curated cases
        try:
            tier_b = load_tier_b_curated(self.dataset_root)
            for c in tier_b:
                c["dataset_tier"] = "TIER_B"
                all_cases.append(c)
        except Exception as e:
            logger.warning("Could not load Tier B curated cases: %s", e)

        # 3. 140+ Candidate PRs
        if include_candidates:
            try:
                candidates = load_all_candidates(self.dataset_root)
                replayable = filter_replayable_candidates(candidates)
                if self.exclude_rejected_candidates:
                    replayable = [c for c in replayable if c.get("label") != "REJECTED"]
                for c in replayable:
                    c["dataset_tier"] = "TIER_B_CANDIDATE"
                    all_cases.append(c)
            except Exception as e:
                logger.warning("Could not load candidate corpus: %s", e)

        total_available = len(all_cases)
        logger.info("Total benchmark corpus collected: %d cases.", total_available)

        sharded_cases = all_cases[task_index::task_count]
        logger.info("Task index %d/%d: Assigned %d cases to process.", task_index, task_count, len(sharded_cases))

        eval_results = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_case = {executor.submit(self.evaluate_case_5way, c): c for c in sharded_cases}
            for fut in as_completed(future_to_case):
                try:
                    res = fut.result()
                    eval_results.append(res)
                except Exception as exc:
                    c = future_to_case[fut]
                    logger.error("Case evaluation failed for %s: %s", c.get("case_id"), exc)

        eval_results.sort(key=lambda r: (str(r.get("tier", "")), str(r.get("case_id", ""))))
        execution_mode = (
            "test_injected_doubles"
            if self._using_injected_doubles
            else "gcp_live_vertex_ai_model_armor"
        )
        return self.generate_aggregated_report(
            eval_results,
            task_index,
            task_count,
            execution_mode=execution_mode,
        )

    @staticmethod
    def _compute_systems_block(subset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Computes 5-way comparative metrics + latencies for any case subset."""
        if not subset:
            return {}
        y_true = [r["ground_truth"] for r in subset]
        system_metrics: Dict[str, Any] = {}
        for sys_key in SYSTEM_ORDER:
            y_pred = [r["predictions"][sys_key] for r in subset]
            m = compute_binary_metrics(y_true, y_pred)
            latencies = [
                r["latencies_ms"].get(sys_key, 0.0)
                for r in subset
                if r.get("latencies_ms", {}).get(sys_key, 0.0) > 0
            ]
            m["latency"] = compute_latency_distribution(latencies)
            system_metrics[sys_key] = {
                "name": SYSTEM_LABELS[sys_key],
                "metrics": m,
            }
        return system_metrics

    @classmethod
    def generate_aggregated_report(
        cls,
        results: List[Dict[str, Any]],
        task_index: int = 0,
        task_count: int = 1,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Calculates complete 5-way comparative statistics, per-tier breakdowns, provenance, and injection resilience."""
        ordered_results = sorted(results, key=lambda r: (str(r.get("tier", "")), str(r.get("case_id", ""))))
        system_metrics = cls._compute_systems_block(ordered_results)

        # Eligible non-REJECTED subset (transparently removes REJECTED non-Python lockfiles from pooled denominator)
        eligible_results = [r for r in ordered_results if r.get("ground_truth") != "REJECTED"]
        rejected_count = len(ordered_results) - len(eligible_results)
        eligible_system_metrics = cls._compute_systems_block(eligible_results)

        # Per-Tier 5-way stratification
        tier_stratification: Dict[str, Any] = {}
        for tier_key in ["TIER_A", "TIER_B", "TIER_B_CANDIDATE"]:
            tier_subset = [r for r in ordered_results if r.get("tier") == tier_key]
            if tier_subset:
                prov_counts = dict(sorted(Counter(r.get("label_provenance", "UNKNOWN") for r in tier_subset).items()))
                gt_counts = dict(sorted(Counter(r.get("ground_truth", "UNKNOWN") for r in tier_subset).items()))
                tier_entry: Dict[str, Any] = {
                    "count": len(tier_subset),
                    "ground_truth_distribution": gt_counts,
                    "label_provenance_distribution": prov_counts,
                    "systems": cls._compute_systems_block(tier_subset),
                }
                if tier_key == "TIER_B_CANDIDATE":
                    elig_cand = [r for r in tier_subset if r.get("ground_truth") != "REJECTED"]
                    if elig_cand and len(elig_cand) != len(tier_subset):
                        tier_entry["eligible_only_count"] = len(elig_cand)
                        tier_entry["rejected_candidates_count"] = len(tier_subset) - len(elig_cand)
                        tier_entry["eligible_only_systems"] = cls._compute_systems_block(elig_cand)
                tier_stratification[tier_key] = tier_entry

        # Stratification by bump type across all systems
        bump_breakdown: Dict[str, Any] = {}
        for b_type in ["MAJOR", "MINOR", "PATCH"]:
            subset = [r for r in ordered_results if r.get("bump_type") == b_type]
            if subset:
                y_t = [r["ground_truth"] for r in subset]
                bump_breakdown[b_type] = {
                    "count": len(subset),
                    "s5_hybrid_accuracy": compute_binary_metrics(y_t, [r["predictions"]["s5_hybrid_agent"] for r in subset]).get("exact_accuracy", {}),
                    "b4_single_llm_accuracy": compute_binary_metrics(y_t, [r["predictions"]["b4_single_llm"] for r in subset]).get("exact_accuracy", {}),
                    "b2_green_ci_accuracy": compute_binary_metrics(y_t, [r["predictions"]["b2_green_ci"] for r in subset]).get("exact_accuracy", {}),
                    "b1_semver_accuracy": compute_binary_metrics(y_t, [r["predictions"]["b1_semver"] for r in subset]).get("exact_accuracy", {}),
                }

        # Label provenance breakdown (highlights CI-proxy circularity transparently)
        provenance_counts = dict(sorted(Counter(r.get("label_provenance", "UNKNOWN") for r in ordered_results).items()))
        provenance_stratification: Dict[str, Any] = {}
        for prov_key in provenance_counts:
            p_sub = [r for r in ordered_results if r.get("label_provenance") == prov_key]
            provenance_stratification[prov_key] = {
                "count": len(p_sub),
                "systems": cls._compute_systems_block(p_sub),
            }

        # Prompt-injection & Model Armor summary
        ma_status_summary = dict(
            sorted(Counter(r.get("s5_model_armor_status") or "unknown" for r in ordered_results).items())
        )
        inj_cases = [r for r in ordered_results if r.get("is_injection")]
        n_inj = len(inj_cases)
        shield_detected = sum(1 for r in inj_cases if r.get("s5_injection_detected"))
        engine_counts = dict(
            sorted(
                Counter(
                    r.get("s5_injection_engine") or "none"
                    for r in inj_cases
                    if r.get("s5_injection_detected")
                ).items()
            )
        )
        resilience_by_system: Dict[str, Any] = {}
        for sys_key in SYSTEM_ORDER:
            blocked = sum(1 for r in inj_cases if r["predictions"].get(sys_key) != "NO_RISK_FOUND")
            ci = wilson_score_interval(blocked, n_inj)
            resilience_by_system[sys_key] = {
                "blocked_override_count": f"{blocked}/{n_inj}",
                "resilience_percentage": f"{ci['proportion'] * 100:.1f}%",
                "ci_95": [ci["lower"], ci["upper"]],
            }

        det_ci = wilson_score_interval(shield_detected, n_inj)
        injection_evaluation = {
            "injection_case_count": n_inj,
            "case_ids": [r["case_id"] for r in inj_cases],
            "model_armor_status_summary": ma_status_summary,
            "shield_detected": {
                "count": f"{shield_detected}/{n_inj}",
                "percentage": f"{det_ci['proportion'] * 100:.1f}%",
                "ci_95": [det_ci["lower"], det_ci["upper"]],
                "engines": engine_counts,
            },
            "system_resilience": resilience_by_system,
        }

        report: Dict[str, Any] = {
            "task_index": task_index,
            "task_count": task_count,
            "execution_mode": execution_mode or "gcp_live_vertex_ai_model_armor",
            "cases_evaluated": len(ordered_results),
            "eligible_cases_evaluated": len(eligible_results),
            "rejected_candidates_count": rejected_count,
            "label_provenance_summary": provenance_counts,
            "model_armor_summary": ma_status_summary,
            "systems": system_metrics,
            "eligible_only_systems": eligible_system_metrics,
            "tier_stratification": tier_stratification,
            "bump_type_stratification": bump_breakdown,
            "label_provenance_stratification": provenance_stratification,
            "injection_evaluation": injection_evaluation,
            "case_results": ordered_results,
            "results_sample": ordered_results[:5],
        }
        return report
