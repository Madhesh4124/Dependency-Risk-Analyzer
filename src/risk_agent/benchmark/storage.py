"""Cloud persistence and shard aggregation for Phase 7 benchmark reports.

Architecture rationale (GCS + Firestore hybrid):
- Google Cloud Storage (GCS) stores the complete raw JSON artifacts (including every
  per-case result in `case_results`, individual Cloud Run Job shards, and merged
  reports) without being constrained by Firestore's 1 MiB per-document limit or
  40k-index-entry ceiling.
- Google Cloud Firestore stores compact (<900 KB) indexed run & shard summary
  documents (`systems`, `tier_stratification`, `bump_type_stratification`,
  `injection_evaluation`, and `gcs_uri`) so dashboards and CI checks can query run
  history in milliseconds without downloading large artifacts.
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from risk_agent.benchmark.phase7_5_injection_runner import Phase75InjectionBenchmarkRunner
from risk_agent.benchmark.scale_runner import ScaleBenchmarkRunner
from risk_agent.config import DEFAULT_CONFIG

logger = logging.getLogger("risk_agent.benchmark.storage")

FIRESTORE_SAFE_LIMIT_BYTES = 900_000  # Strict safety headroom under Firestore's 1 MiB (1,048,576 B) limit

try:
    from google.cloud import storage as gcs_storage
    HAS_GCS = True
except ImportError:
    HAS_GCS = False

try:
    from google.cloud import firestore
    HAS_FIRESTORE = True
except ImportError:
    HAS_FIRESTORE = False


def generate_run_id(prefix: str = "run") -> str:
    """Generates a deterministic, lexicographically sortable benchmark run identifier."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{ts}-{uuid.uuid4().hex[:6]}"


def build_firestore_summary(
    report: Dict[str, Any],
    run_id: str,
    gcs_uri: Optional[str] = None,
    is_shard: bool = False,
) -> Dict[str, Any]:
    """Builds a compact, queryable Firestore document safely below the 1 MiB document cap.

    Strips unbounded `case_results` arrays (which belong in GCS) and enforces a byte-size guard.
    """
    benchmark_phase = report.get("benchmark_phase") or (
        "phase_7_5" if "detectors" in report else "phase_7"
    )
    if benchmark_phase == "phase_7_5":
        summary: Dict[str, Any] = {
            "run_id": run_id,
            "benchmark_phase": "phase_7_5",
            "dataset": report.get("dataset", "prodnull/cloneguard (Apache-2.0)"),
            "generated_at": report.get("generated_at"),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "is_shard": is_shard,
            "is_partial": bool(report.get("is_partial", False)),
            "task_index": report.get("task_index", 0),
            "task_count": report.get("task_count", 1),
            "execution_mode": report.get("execution_mode", "unspecified"),
            "request_delay_ms": report.get("request_delay_ms", 0),
            "runtime_config": report.get("runtime_config", {}),
            "cases_evaluated": report.get("cases_evaluated", 0),
            "core_domain_cases_evaluated": report.get("core_domain_cases_evaluated", 0),
            "injection_cases_count": report.get("injection_cases_count", 0),
            "benign_cases_count": report.get("benign_cases_count", 0),
            "detectors": report.get("detectors", {}),
            "core_domain_detectors": report.get("core_domain_detectors", {}),
            "model_armor_lift": report.get("model_armor_lift", {}),
            "split_breakdown": report.get("split_breakdown", {}),
            "attack_category_breakdown": report.get("attack_category_breakdown", {}),
            "benign_content_type_breakdown": report.get("benign_content_type_breakdown", {}),
            "model_armor_summary": report.get("model_armor_summary", {}),
            "gcs_uri": gcs_uri,
            "full_report_in_gcs": bool(gcs_uri),
        }
    else:
        summary = {
            "run_id": run_id,
            "benchmark_phase": report.get("benchmark_phase", "phase_7"),
            "dataset": report.get("dataset", "PyRiskBench (madheshraj/python-dependency-upgrade-risk-benchmark)"),
            "generated_at": report.get("generated_at"),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "is_shard": is_shard,
            "is_partial": bool(report.get("is_partial", False)),
            "task_index": report.get("task_index", 0),
            "task_count": report.get("task_count", 1),
            "execution_mode": report.get("execution_mode", "unspecified"),
            "runtime_config": report.get("runtime_config", {}),
            "cases_evaluated": report.get("cases_evaluated", 0),
            "eligible_cases_evaluated": report.get("eligible_cases_evaluated", 0),
            "rejected_candidates_count": report.get("rejected_candidates_count", 0),
            "label_provenance_summary": report.get("label_provenance_summary", {}),
            "model_armor_summary": report.get("model_armor_summary", {}),
            "systems": report.get("systems", {}),
            "eligible_only_systems": report.get("eligible_only_systems", {}),
            "tier_stratification": report.get("tier_stratification", {}),
            "bump_type_stratification": report.get("bump_type_stratification", {}),
            "injection_evaluation": report.get("injection_evaluation", {}),
            "gcs_uri": gcs_uri,
            "full_report_in_gcs": bool(gcs_uri),
        }
    if "merged_from_shards" in report:
        summary["merged_from_shards"] = report["merged_from_shards"]
    if "missing_shard_indices" in report:
        summary["missing_shard_indices"] = report["missing_shard_indices"]

    # Enforce strict <900 KB safety ceiling before sending to Firestore
    encoded_size = len(json.dumps(summary).encode("utf-8"))
    if encoded_size > FIRESTORE_SAFE_LIMIT_BYTES:
        logger.warning(
            "Firestore summary document (%d bytes) exceeds safe cap (%d bytes); pruning optional nested details.",
            encoded_size,
            FIRESTORE_SAFE_LIMIT_BYTES,
        )
        for optional_key in (
            "eligible_only_systems",
            "bump_type_stratification",
            "benign_content_type_breakdown",
            "split_breakdown",
        ):
            summary.pop(optional_key, None)
        encoded_size = len(json.dumps(summary).encode("utf-8"))
        if encoded_size > FIRESTORE_SAFE_LIMIT_BYTES:
            summary.pop("tier_stratification", None)
            summary.pop("attack_category_breakdown", None)
        summary["payload_pruned_for_firestore_limit"] = True

    return summary


def merge_shard_reports(
    shard_reports: List[Dict[str, Any]],
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Merges sharded Cloud Run Job reports into a single combined report with exact global stats.

    Recalculates Wilson 95% CIs, per-tier metrics, and latency percentiles over the combined
    per-case records rather than averaging shard-level summary statistics.
    """
    if not shard_reports:
        raise ValueError("Cannot merge empty shard list")

    is_phase7_5 = any(s.get("benchmark_phase") == "phase_7_5" or "detectors" in s for s in shard_reports)
    modes = {s["execution_mode"] for s in shard_reports if s.get("execution_mode")}
    mode_str = next(iter(modes)) if len(modes) == 1 else "mixed"

    if is_phase7_5:
        deduped_p75: Dict[str, Dict[str, Any]] = {}
        delay_vals = [int(s.get("request_delay_ms", 0)) for s in shard_reports if s.get("request_delay_ms") is not None]
        for shard in shard_reports:
            for c in shard.get("case_results") or shard.get("results_sample") or []:
                deduped_p75[str(c.get("case_id", ""))] = c
        merged = Phase75InjectionBenchmarkRunner.generate_aggregated_report(
            results=list(deduped_p75.values()),
            task_index=0,
            task_count=1,
            execution_mode=mode_str,
            request_delay_ms=max(delay_vals) if delay_vals else 0,
        )
    else:
        deduped_cases: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for shard in shard_reports:
            cases = shard.get("case_results") or shard.get("results_sample") or []
            for c in cases:
                key = (str(c.get("tier", "")), str(c.get("case_id", "")))
                deduped_cases[key] = c

        all_cases = list(deduped_cases.values())
        merged = ScaleBenchmarkRunner.generate_aggregated_report(
            results=all_cases,
            task_index=0,
            task_count=1,
            execution_mode=mode_str,
        )
    merged["merged_from_shards"] = len(shard_reports)
    merged["shard_task_indices"] = sorted(
        int(s.get("task_index", 0)) for s in shard_reports
    )
    runtime_cfgs = [s["runtime_config"] for s in shard_reports if isinstance(s.get("runtime_config"), dict) and s["runtime_config"]]
    if runtime_cfgs and "runtime_config" not in merged:
        merged["runtime_config"] = runtime_cfgs[0]
    merged.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    if run_id:
        merged["run_id"] = run_id
    return merged


class BenchmarkStorage:
    """Dual persistence manager storing raw benchmark artifacts in GCS and indexed summaries in Firestore."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        gcs_bucket: Optional[str] = None,
        gcs_prefix: Optional[str] = None,
        firestore_collection: Optional[str] = None,
        storage_client: Optional[Any] = None,
        firestore_client: Optional[Any] = None,
        enable_firestore: bool = True,
    ):
        self.project_id = project_id or DEFAULT_CONFIG.gcp_project_id
        self.gcs_bucket_name = gcs_bucket if gcs_bucket is not None else DEFAULT_CONFIG.benchmark_gcs_bucket
        self.gcs_prefix = (gcs_prefix or DEFAULT_CONFIG.benchmark_gcs_prefix).strip("/")
        self.firestore_collection = firestore_collection or DEFAULT_CONFIG.benchmark_firestore_collection

        self._gcs_client = storage_client
        self._firestore_client = firestore_client
        self._enable_firestore = enable_firestore

        if self._gcs_client is None and self.gcs_bucket_name and HAS_GCS:
            try:
                self._gcs_client = gcs_storage.Client(project=self.project_id)
            except Exception as e:
                logger.warning("GCS client initialization failed (%s); GCS upload disabled.", e)
                self._gcs_client = None

        if self._firestore_client is None and self._enable_firestore and HAS_FIRESTORE:
            try:
                self._firestore_client = firestore.Client(project=self.project_id)
            except Exception as e:
                logger.warning("Firestore client initialization failed (%s); Firestore index disabled.", e)
                self._firestore_client = None

    @property
    def is_gcs_active(self) -> bool:
        return bool(self._gcs_client is not None and self.gcs_bucket_name)

    @property
    def is_firestore_active(self) -> bool:
        return bool(self._firestore_client is not None and self._enable_firestore)

    def _upload_gcs_json(self, blob_path: str, payload: Dict[str, Any]) -> str:
        bucket = self._gcs_client.bucket(self.gcs_bucket_name)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(
            json.dumps(payload, indent=2, default=str),
            content_type="application/json",
        )
        return f"gs://{self.gcs_bucket_name}/{blob_path}"

    def save_report(
        self,
        report: Dict[str, Any],
        run_id: str,
        write_latest: bool = True,
    ) -> Dict[str, Any]:
        """Persists a shard or full benchmark report to GCS (full artifact) and Firestore (compact summary)."""
        task_index = int(report.get("task_index", 0))
        task_count = int(report.get("task_count", 1))
        is_sharded_slice = task_count > 1 and "merged_from_shards" not in report

        status: Dict[str, Any] = {
            "run_id": run_id,
            "gcs_active": self.is_gcs_active,
            "firestore_active": self.is_firestore_active,
            "gcs_shard_uri": None,
            "gcs_report_uri": None,
            "gcs_latest_uri": None,
            "firestore_run_doc": None,
            "firestore_shard_doc": None,
            "errors": [],
        }

        primary_gcs_uri: Optional[str] = None

        # 1. Google Cloud Storage (raw full artifact with all `case_results`)
        if self.is_gcs_active:
            try:
                shard_blob = f"{self.gcs_prefix}/{run_id}/shards/task_{task_index:04d}_of_{task_count:04d}.json"
                if is_sharded_slice:
                    shard_uri = self._upload_gcs_json(shard_blob, report)
                    status["gcs_shard_uri"] = shard_uri
                    primary_gcs_uri = shard_uri
                    logger.info("Uploaded benchmark shard to %s", shard_uri)
                else:
                    report_blob = f"{self.gcs_prefix}/{run_id}/report.json"
                    report_uri = self._upload_gcs_json(report_blob, report)
                    status["gcs_report_uri"] = report_uri
                    primary_gcs_uri = report_uri
                    logger.info("Uploaded full benchmark report to %s", report_uri)
                    if write_latest:
                        latest_blob = f"{self.gcs_prefix}/latest.json"
                        status["gcs_latest_uri"] = self._upload_gcs_json(latest_blob, report)
            except Exception as e:
                logger.error("Failed uploading benchmark artifact to GCS: %s", e)
                status["errors"].append(f"gcs_error: {e}")

        # 2. Google Cloud Firestore (compact summary index <900 KB)
        if self.is_firestore_active:
            try:
                run_ref = self._firestore_client.collection(self.firestore_collection).document(run_id)
                if is_sharded_slice:
                    shard_id = f"task_{task_index:04d}"
                    shard_summary = build_firestore_summary(
                        report, run_id=run_id, gcs_uri=primary_gcs_uri, is_shard=True
                    )
                    run_ref.collection("shards").document(shard_id).set(shard_summary)
                    status["firestore_shard_doc"] = f"{self.firestore_collection}/{run_id}/shards/{shard_id}"
                    # Maintain minimal parent metadata doc without contended metric overwrites
                    run_ref.set(
                        {
                            "run_id": run_id,
                            "status": "SHARDS_IN_PROGRESS",
                            "task_count": task_count,
                            "execution_mode": report.get("execution_mode", "unspecified"),
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                            "gcs_prefix": f"gs://{self.gcs_bucket_name}/{self.gcs_prefix}/{run_id}" if self.is_gcs_active else None,
                        },
                        merge=True,
                    )
                    status["firestore_run_doc"] = f"{self.firestore_collection}/{run_id}"
                else:
                    run_summary = build_firestore_summary(
                        report, run_id=run_id, gcs_uri=primary_gcs_uri, is_shard=False
                    )
                    run_summary["status"] = "PARTIAL" if report.get("is_partial") else "COMPLETED"
                    run_ref.set(run_summary)
                    status["firestore_run_doc"] = f"{self.firestore_collection}/{run_id}"
                logger.info("Saved Firestore benchmark index doc: %s", status["firestore_shard_doc"] or status["firestore_run_doc"])
            except Exception as e:
                logger.error("Failed saving benchmark summary to Firestore: %s", e)
                status["errors"].append(f"firestore_error: {e}")

        return status

    def list_gcs_shards(self, run_id: str) -> List[Dict[str, Any]]:
        """Downloads and parses all shard JSON files for `run_id` from GCS."""
        if not self.is_gcs_active:
            raise RuntimeError("GCS client/bucket is not configured; cannot fetch shards from GCS.")

        prefix = f"{self.gcs_prefix}/{run_id}/shards/"
        shards: List[Dict[str, Any]] = []
        blobs = self._gcs_client.list_blobs(self.gcs_bucket_name, prefix=prefix)
        for blob in blobs:
            if blob.name.endswith(".json"):
                raw = blob.download_as_text(encoding="utf-8")
                shards.append(json.loads(raw))
        return shards

    def merge_run_from_gcs(
        self,
        run_id: str,
        expected_tasks: Optional[int] = None,
        wait_seconds: int = 0,
        poll_interval_seconds: int = 5,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Collects shard artifacts for `run_id` from GCS, merges them, and persists the final report."""
        deadline = time.time() + max(0, wait_seconds)
        shards = self.list_gcs_shards(run_id)
        inferred_expected = expected_tasks or (
            max((int(s.get("task_count", 1)) for s in shards), default=1) if shards else None
        )
        while inferred_expected and len(shards) < inferred_expected and time.time() < deadline:
            logger.info(
                "Waiting for GCS shards for run %s (%d/%d available)...",
                run_id,
                len(shards),
                inferred_expected,
            )
            time.sleep(poll_interval_seconds)
            shards = self.list_gcs_shards(run_id)
            if not expected_tasks and shards:
                inferred_expected = max(int(s.get("task_count", 1)) for s in shards)

        if not shards:
            return None, {"run_id": run_id, "errors": [f"No shard JSON blobs found under {self.gcs_prefix}/{run_id}/shards/"]}

        target_count = expected_tasks or max((int(s.get("task_count", 1)) for s in shards), default=1)
        present_indices = {int(s.get("task_index", 0)) for s in shards}
        missing_indices = [i for i in range(target_count) if i not in present_indices]
        is_complete = len(missing_indices) == 0 and len(shards) >= target_count

        if not is_complete and wait_seconds > 0:
            msg = (
                f"Timed out waiting for all shards for run {run_id}: "
                f"{len(shards)}/{target_count} present (missing={missing_indices}). "
                "Individual shards remain safely stored in GCS; run --merge-shards after remaining tasks finish."
            )
            logger.warning(msg)
            return None, {
                "run_id": run_id,
                "errors": [msg],
                "shards_available": len(shards),
                "expected_tasks": target_count,
                "missing_shard_indices": missing_indices,
            }

        merged = merge_shard_reports(shards, run_id=run_id)
        if not is_complete:
            merged["is_partial"] = True
            merged["expected_tasks"] = target_count
            merged["missing_shard_indices"] = missing_indices
            logger.warning(
                "Merging PARTIAL shard set for %s (%d/%d present, missing=%s); latest.json will not be overwritten.",
                run_id,
                len(shards),
                target_count,
                missing_indices,
            )

        save_status = self.save_report(merged, run_id=run_id, write_latest=is_complete)
        save_status["shards_merged"] = len(shards)
        save_status["is_partial"] = not is_complete
        if missing_indices:
            save_status["missing_shard_indices"] = missing_indices
        return merged, save_status
