"""Phase 7 Master Scale Evaluation CLI Harness (GCP Cloud-Only).

Designed exclusively for execution inside Google Cloud Run Jobs (`pyriskbench-scale-eval`)
with live Vertex AI Gemini (`gemini-3.1-flash-lite`), primary fail-closed Google Cloud
Model Armor inspection, and persistent GCS + Firestore storage:
    python benchmark/scale_harness.py --concurrency 4 --gcs-bucket my-bucket
    python benchmark/scale_harness.py --merge-shards --run-id run-20261110T120000Z-abc123 --gcs-bucket my-bucket

Reads:
    CLOUD_RUN_JOB / CLOUD_RUN_EXECUTION (enforces GCP Cloud Run Job execution)
    CLOUD_RUN_TASK_INDEX (default 0)
    CLOUD_RUN_TASK_COUNT (default 1)
    PYRISKBENCH_DATASET_DIR (optional)
    BENCHMARK_GCS_BUCKET (required)
    BENCHMARK_FIRESTORE_COLLECTION (default benchmark_runs)
"""

import argparse
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict

# Add project root and src to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

from risk_agent.benchmark.scale_runner import ScaleBenchmarkRunner
from risk_agent.benchmark.storage import BenchmarkStorage, generate_run_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark.scale_harness")


def _print_systems_table(title: str, systems: Dict[str, Any]):
    if not systems:
        return
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)
    print(f"{'System':<42} | {'Exact Acc':<11} | {'False Safe Rate':<15} | {'False Alarm'}")
    print("-" * 88)
    for _, data in systems.items():
        name = data["name"][:40]
        m = data.get("metrics", {})
        acc = m.get("exact_accuracy", {}).get("percentage", "N/A")
        fnr = m.get("false_no_risk_found_rate", {}).get("percentage", "N/A")
        fpr = m.get("false_alarm_rate", {}).get("percentage", "N/A")
        print(f"{name:<42} | {acc:<11} | {fnr:<15} | {fpr}")
    print("=" * 88)


def print_report_summary(report: Dict[str, Any], cloud_status: Dict[str, Any] | None = None):
    """Prints overall, eligible-only, per-tier, injection, Model Armor, and persistence summaries."""
    n_cases = report.get("cases_evaluated", 0)
    _print_systems_table(
        f"5-WAY COMPARATIVE EVALUATION SUMMARY (N = {n_cases}, 95% Wilson Score CIs)",
        report.get("systems", {}),
    )

    if report.get("rejected_candidates_count", 0) > 0:
        n_elig = report.get("eligible_cases_evaluated", 0)
        _print_systems_table(
            f"ELIGIBLE-ONLY SUMMARY (Excluding {report['rejected_candidates_count']} REJECTED Candidates, N = {n_elig})",
            report.get("eligible_only_systems", {}),
        )

    for tier_key, tier_data in report.get("tier_stratification", {}).items():
        cnt = tier_data.get("count", 0)
        prov = tier_data.get("label_provenance_distribution", {})
        prov_str = ", ".join(f"{k}={v}" for k, v in prov.items())
        _print_systems_table(
            f"PER-TIER BREAKDOWN: {tier_key} (N = {cnt} | Provenance: {prov_str})",
            tier_data.get("systems", {}),
        )

    inj = report.get("injection_evaluation", {})
    if inj.get("injection_case_count", 0) > 0:
        shield = inj.get("shield_detected", {})
        resil = inj.get("system_resilience", {})
        print(
            f"\nInjection Evaluation ({inj['injection_case_count']} cases): "
            f"Shield Detected = {shield.get('count')} ({shield.get('percentage')}), "
            f"B4 Single LLM Resilience = {resil.get('b4_single_llm', {}).get('blocked_override_count')}, "
            f"S5 Hybrid Resilience = {resil.get('s5_hybrid_agent', {}).get('blocked_override_count')}"
        )

    ma_sum = report.get("model_armor_summary", {})
    if ma_sum:
        print(f"Model Armor Inspection Summary: {ma_sum}")

    if cloud_status is not None:
        print(
            f"\nCloud Persistence (run_id={cloud_status.get('run_id')}): "
            f"GCS={cloud_status.get('gcs_report_uri') or cloud_status.get('gcs_shard_uri') or 'disabled'}, "
            f"Firestore={cloud_status.get('firestore_shard_doc') or cloud_status.get('firestore_run_doc') or 'disabled'}"
        )


def _enforce_cloud_run_execution() -> None:
    """Blocks local benchmark execution; enforces Google Cloud Run Jobs runtime."""
    if not (os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION")):
        raise RuntimeError(
            "Local Phase 7 benchmark execution has been disabled. "
            "Run Phase 7 inside Google Cloud Run Jobs (`gcloud run jobs execute pyriskbench-scale-eval ...`) "
            "using live Vertex AI + Google Cloud Model Armor (see docs/guides/phase_7_gcp_guide.md)."
        )


def main():
    parser = argparse.ArgumentParser(description="Phase 7 GCP Cloud Run 5-Way Benchmark Runner")
    parser.add_argument("--concurrency", type=int, default=4, help="Worker thread pool concurrency")
    parser.add_argument("--dataset-dir", type=str, default=None, help="Path to local dataset or cache")
    parser.add_argument("--run-id", type=str, default=None, help="Benchmark run identifier for GCS/Firestore")
    parser.add_argument("--gcs-bucket", type=str, default=None, help="GCS bucket for storing full JSON artifacts")
    parser.add_argument("--firestore-collection", type=str, default=None, help="Firestore collection for run summaries")
    parser.add_argument("--exclude-rejected", action="store_true", help="Exclude REJECTED candidates prior to execution")
    parser.add_argument("--merge-shards", action="store_true", help="Merge GCS shards for --run-id into a unified report")
    parser.add_argument("--wait-for-shards-seconds", type=int, default=0, help="Wait timeout for sibling GCS shards when merging")
    args = parser.parse_args()

    # Cloud Run Jobs environment variable sharding
    task_index = int(os.getenv("CLOUD_RUN_TASK_INDEX", "0"))
    task_count = int(os.getenv("CLOUD_RUN_TASK_COUNT", "1"))
    run_id = (
        args.run_id
        or os.getenv("BENCHMARK_RUN_ID")
        or os.getenv("CLOUD_RUN_EXECUTION")
        or generate_run_id()
    )

    storage = BenchmarkStorage(
        gcs_bucket=args.gcs_bucket,
        firestore_collection=args.firestore_collection,
    )
    if not storage.is_gcs_active:
        raise RuntimeError(
            "Active Google Cloud Storage bucket is required (--gcs-bucket or BENCHMARK_GCS_BUCKET)."
        )

    # Shard merge mode (merges GCS shards from parallel Cloud Run tasks -> GCS + Firestore)
    if args.merge_shards:
        logger.info("Merging GCS shards for run_id=%s...", run_id)
        merged_report, cloud_status = storage.merge_run_from_gcs(
            run_id=run_id,
            expected_tasks=task_count if task_count > 1 else None,
            wait_seconds=args.wait_for_shards_seconds,
        )
        if not merged_report:
            raise RuntimeError(f"Shard merge failed for run_id={run_id}: {cloud_status.get('errors')}")
        print_report_summary(merged_report, cloud_status)
        return

    # Enforce GCP Cloud Run Jobs execution environment for live evaluation
    _enforce_cloud_run_execution()

    dataset_root = Path(args.dataset_dir) if args.dataset_dir else None

    logger.info("=" * 70)
    logger.info("   PHASE 7: GCP CLOUD RUN 5-WAY BENCHMARK (LIVE VERTEX AI + MODEL ARMOR)")
    logger.info("=" * 70)
    logger.info("Run ID:       %s", run_id)
    logger.info("Cloud Job:    %s (%s)", os.getenv("CLOUD_RUN_JOB"), os.getenv("CLOUD_RUN_EXECUTION"))
    logger.info("Task Index:   %d / %d", task_index, task_count)
    logger.info("Concurrency:  %d", args.concurrency)
    logger.info("GCS Bucket:   %s", storage.gcs_bucket_name)
    logger.info("Dataset Root: %s", dataset_root or "Auto-resolved (KaggleHub or container /app/benchmark)")

    runner = ScaleBenchmarkRunner(
        dataset_root=dataset_root,
        concurrency=args.concurrency,
        exclude_rejected_candidates=args.exclude_rejected,
        require_gcp=True,
    )
    logger.info(
        "Vertex AI:    model=%s, location=%s (B4=%s)",
        runner.hybrid_agent.extractor.model_name,
        runner.hybrid_agent.extractor.location,
        runner.single_call_baseline.location,
    )
    logger.info(
        "Model Armor:  template=%s, location=%s, fail_closed=%s",
        runner.injection_detector.model_armor_template,
        runner.injection_detector.model_armor_location,
        runner.injection_detector.fail_closed,
    )

    report = runner.run_sharded_benchmark(
        task_index=task_index,
        task_count=task_count,
        include_tier_a=True,
        include_candidates=True,
    )
    report["run_id"] = run_id

    cloud_status = storage.save_report(report, run_id=run_id, write_latest=(task_count == 1))
    if cloud_status.get("errors"):
        raise RuntimeError(f"Cloud persistence errors for run_id={run_id}: {cloud_status['errors']}")

    if task_count > 1 and task_index == 0 and args.wait_for_shards_seconds > 0:
        logger.info("Task 0 attempting automatic shard merge (wait=%ds)...", args.wait_for_shards_seconds)
        merged_report, merge_status = storage.merge_run_from_gcs(
            run_id=run_id,
            expected_tasks=task_count,
            wait_seconds=args.wait_for_shards_seconds,
        )
        if merged_report is not None:
            report = merged_report
            cloud_status = merge_status

    print_report_summary(report, cloud_status)


if __name__ == "__main__":
    main()
