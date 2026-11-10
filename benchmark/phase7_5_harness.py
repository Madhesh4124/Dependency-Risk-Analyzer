"""Phase 7.5 Dedicated Prompt Injection Detection Benchmark CLI (GCP Cloud Run Only).

Designed for Google Cloud Run Jobs (`pyriskbench-phase7-5-injection-eval`) evaluating
detection-only performance on the `prodnull/cloneguard` corpus (`N = 539`) using live
Google Cloud Model Armor (`asia-south1`) + Local Normalization & Heuristics (and optional
Vertex AI Gemini `location=global` comparison via `--include-llm-classifier`), with
inter-request pacing (`--request-delay-ms`) to prevent 429 throttling:

    python benchmark/phase7_5_harness.py --concurrency 2 --request-delay-ms 350 --gcs-bucket my-bucket
    python benchmark/phase7_5_harness.py --merge-shards --run-id run-20261110T120000Z-abc123 --gcs-bucket my-bucket
"""

import argparse
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

from risk_agent.benchmark.phase7_5_injection_runner import Phase75InjectionBenchmarkRunner
from risk_agent.benchmark.storage import BenchmarkStorage, generate_run_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark.phase7_5_harness")


def _print_detectors_table(title: str, detectors: Dict[str, Any]) -> None:
    if not detectors:
        return
    print("\n" + "=" * 96)
    print(title)
    print("=" * 96)
    print(
        f"{'Detector':<44} | {'Accuracy':<10} | {'TPR (Recall)':<12} | {'FPR':<10} | {'F1':<6} | {'p50 ms'}"
    )
    print("-" * 96)
    for _, data in detectors.items():
        name = data["name"][:42]
        m = data.get("metrics", {})
        acc = m.get("accuracy", {}).get("percentage", "N/A")
        tpr = m.get("detection_recall_tpr", {}).get("percentage", "N/A")
        fpr = m.get("false_positive_rate", {}).get("percentage", "N/A")
        f1 = f"{m.get('f1_score', 0.0):.3f}"
        p50 = f"{m.get('latency', {}).get('p50_ms', 0.0):.1f}"
        print(f"{name:<44} | {acc:<10} | {tpr:<12} | {fpr:<10} | {f1:<6} | {p50}")
    print("=" * 96)


def print_phase7_5_summary(report: Dict[str, Any], cloud_status: Optional[Dict[str, Any]] = None) -> None:
    """Prints pooled, core-domain, Model Armor lift, category breakdown, and GCS/Firestore links."""
    n_cases = report.get("cases_evaluated", 0)
    _print_detectors_table(
        f"PHASE 7.5 PROMPT INJECTION DETECTION (CloneGuard Full Corpus, N = {n_cases}, 95% Wilson CIs)",
        report.get("detectors", {}),
    )

    core = report.get("core_domain_detectors", {})
    if core:
        n_core = report.get("core_domain_cases_evaluated", 0)
        _print_detectors_table(
            f"CORE DOMAIN SUBSET (Excluding Out-of-Domain implicit_instruction, N = {n_core})",
            core,
        )

    lift = report.get("model_armor_lift", {})
    if lift:
        print(
            f"\nModel Armor Semantic Lift: Local={lift.get('local_only_catches')}, "
            f"Hybrid={lift.get('hybrid_total_catches')}, "
            f"Model-Armor-Only Catches=+{lift.get('model_armor_only_catches')} "
            f"(Recall Delta={lift.get('recall_delta_pct')}%, FPR Delta={lift.get('fpr_delta_pct')}%)"
        )

    cats = report.get("attack_category_breakdown", {})
    if cats:
        print("\nAttack Category Detection Recall (D1 Local vs D2 Model Armor + Local):")
        for cat, stats in cats.items():
            tag = "" if stats.get("is_core_domain", True) else " [out-of-domain]"
            print(
                f"  - {cat}{tag}: D1={stats['d1_recall']['count']} ({stats['d1_recall']['percentage']}) | "
                f"D2={stats['d2_recall']['count']} ({stats['d2_recall']['percentage']})"
            )

    ma_sum = report.get("model_armor_summary", {})
    if ma_sum:
        print(f"\nModel Armor Telemetry: {ma_sum}")

    if cloud_status is not None:
        print(
            f"\nCloud Persistence (run_id={cloud_status.get('run_id')}): "
            f"GCS={cloud_status.get('gcs_report_uri') or cloud_status.get('gcs_shard_uri') or 'disabled'}, "
            f"Firestore={cloud_status.get('firestore_shard_doc') or cloud_status.get('firestore_run_doc') or 'disabled'}"
        )


def _enforce_cloud_run_execution() -> None:
    """Blocks local live execution; enforces Google Cloud Run Jobs runtime."""
    if not (os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION")):
        raise RuntimeError(
            "Local Phase 7.5 benchmark execution has been disabled. "
            "Run Phase 7.5 inside Google Cloud Run Jobs (`gcloud run jobs execute pyriskbench-phase7-5-injection-eval ...`) "
            "with live Google Cloud Model Armor (see docs/guides/phase_7_5_injection_benchmark_guide.md)."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 7.5 GCP Cloud Run Prompt Injection Detection Benchmark")
    parser.add_argument("--concurrency", type=int, default=2, help="Worker thread concurrency (default 2)")
    parser.add_argument(
        "--request-delay-ms",
        type=int,
        default=350,
        help="Inter-request pacing delay in ms before GCP Model Armor / Gemini API calls (prevents 429)",
    )
    parser.add_argument("--dataset-dir", type=str, default=None, help="Path to CloneGuard benchmark JSONs")
    parser.add_argument("--max-cases", type=int, default=None, help="Optional stratified cap on total samples")
    parser.add_argument("--exclude-implicit", action="store_true", help="Exclude out-of-domain implicit_instruction rows")
    parser.add_argument(
        "--include-llm-classifier",
        action="store_true",
        help="Also run D3: Direct Vertex AI Gemini (location=global) classifier baseline",
    )
    parser.add_argument("--run-id", type=str, default=None, help="Benchmark run ID for GCS/Firestore")
    parser.add_argument("--gcs-bucket", type=str, default=None, help="GCS bucket for full JSON artifacts")
    parser.add_argument(
        "--gcs-prefix",
        type=str,
        default=os.getenv("BENCHMARK_GCS_PREFIX", "benchmarks/phase7_5"),
        help="GCS key prefix (default benchmarks/phase7_5)",
    )
    parser.add_argument(
        "--firestore-collection",
        type=str,
        default=os.getenv("BENCHMARK_FIRESTORE_COLLECTION", "phase7_5_injection_runs"),
        help="Firestore collection (default phase7_5_injection_runs)",
    )
    parser.add_argument("--merge-shards", action="store_true", help="Merge GCS shards for --run-id")
    parser.add_argument("--wait-for-shards-seconds", type=int, default=0, help="Wait timeout for sibling shards")
    args = parser.parse_args()

    task_index = int(os.getenv("CLOUD_RUN_TASK_INDEX", "0"))
    task_count = int(os.getenv("CLOUD_RUN_TASK_COUNT", "1"))
    run_id = (
        args.run_id
        or os.getenv("BENCHMARK_RUN_ID")
        or os.getenv("CLOUD_RUN_EXECUTION")
        or generate_run_id(prefix="p75")
    )

    storage = BenchmarkStorage(
        gcs_bucket=args.gcs_bucket,
        gcs_prefix=args.gcs_prefix,
        firestore_collection=args.firestore_collection,
    )
    if not storage.is_gcs_active:
        raise RuntimeError(
            "Active Google Cloud Storage bucket is required (--gcs-bucket or BENCHMARK_GCS_BUCKET)."
        )

    if args.merge_shards:
        logger.info("Merging Phase 7.5 GCS shards for run_id=%s...", run_id)
        merged_report, cloud_status = storage.merge_run_from_gcs(
            run_id=run_id,
            expected_tasks=task_count if task_count > 1 else None,
            wait_seconds=args.wait_for_shards_seconds,
        )
        if not merged_report:
            raise RuntimeError(f"Phase 7.5 shard merge failed for run_id={run_id}: {cloud_status.get('errors')}")
        print_phase7_5_summary(merged_report, cloud_status)
        return

    _enforce_cloud_run_execution()

    dataset_dir = Path(args.dataset_dir) if args.dataset_dir else None
    delay_seconds = max(0.0, args.request_delay_ms / 1000.0)

    logger.info("=" * 72)
    logger.info("   PHASE 7.5: GCP CLOUD RUN PROMPT INJECTION BENCHMARK (CLONEGUARD)")
    logger.info("=" * 72)
    logger.info("Run ID:        %s", run_id)
    logger.info("Cloud Job:     %s (%s)", os.getenv("CLOUD_RUN_JOB"), os.getenv("CLOUD_RUN_EXECUTION"))
    logger.info("Task Index:    %d / %d", task_index, task_count)
    logger.info("Concurrency:   %d", args.concurrency)
    logger.info("Request Delay: %d ms (+ jitter & 429 exponential backoff)", args.request_delay_ms)
    logger.info("GCS Bucket:    %s (prefix=%s)", storage.gcs_bucket_name, storage.gcs_prefix)
    logger.info("LLM Baseline:  %s", "enabled (location=global)" if args.include_llm_classifier else "disabled (detection-only)")

    runner = Phase75InjectionBenchmarkRunner(
        dataset_dir=dataset_dir,
        concurrency=args.concurrency,
        request_delay_seconds=delay_seconds,
        exclude_implicit=args.exclude_implicit,
        max_cases=args.max_cases,
        include_llm_classifier=args.include_llm_classifier,
        require_gcp=True,
    )
    logger.info(
        "Model Armor:   template=%s, location=%s, fail_closed=%s, multilang=%s",
        runner.hybrid_detector.model_armor_template,
        runner.hybrid_detector.model_armor_location,
        runner.hybrid_detector.fail_closed,
        runner.hybrid_detector.enable_multilang,
    )

    report = runner.run_sharded_benchmark(task_index=task_index, task_count=task_count)
    report["run_id"] = run_id

    cloud_status = storage.save_report(report, run_id=run_id, write_latest=(task_count == 1))
    if cloud_status.get("errors"):
        raise RuntimeError(f"Cloud persistence errors for run_id={run_id}: {cloud_status['errors']}")

    if task_count > 1 and task_index == 0 and args.wait_for_shards_seconds > 0:
        logger.info("Task 0 attempting automatic Phase 7.5 shard merge (wait=%ds)...", args.wait_for_shards_seconds)
        merged_report, merge_status = storage.merge_run_from_gcs(
            run_id=run_id,
            expected_tasks=task_count,
            wait_seconds=args.wait_for_shards_seconds,
        )
        if merged_report is not None:
            if merge_status.get("errors"):
                raise RuntimeError(
                    f"Phase 7.5 merged report persistence errors for run_id={run_id}: {merge_status['errors']}"
                )
            report = merged_report
            cloud_status = merge_status
        else:
            logger.warning(
                "Task 0 auto-merge deferred (%s). Shards are saved in GCS; run --merge-shards after remaining tasks complete.",
                merge_status.get("errors"),
            )

    print_phase7_5_summary(report, cloud_status)


if __name__ == "__main__":
    main()
