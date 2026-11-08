"""Phase 7 Master Scale Evaluation CLI Harness.

Can be run locally or inside a Google Cloud Run Job:
    python benchmark/scale_harness.py
    python benchmark/scale_harness.py --use-live-llm --concurrency 8

Reads:
    CLOUD_RUN_TASK_INDEX (default 0)
    CLOUD_RUN_TASK_COUNT (default 1)
    PYRISKBENCH_DATASET_DIR (optional)
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Add project root and src to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

from risk_agent.benchmark.scale_runner import ScaleBenchmarkRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark.scale_harness")


def main():
    parser = argparse.ArgumentParser(description="Phase 7 Cloud-Scale 5-Way Benchmark Runner")
    parser.add_argument("--use-live-llm", action="store_true", help="Use live Vertex AI Gemini API calls")
    parser.add_argument("--concurrency", type=int, default=4, help="Worker thread pool concurrency")
    parser.add_argument("--dataset-dir", type=str, default=None, help="Path to local dataset or cache")
    parser.add_argument("--output", type=str, default="benchmark/phase7_scale_report.json", help="Output path for JSON report")
    args = parser.parse_args()

    # Cloud Run Jobs environment variable sharding
    task_index = int(os.getenv("CLOUD_RUN_TASK_INDEX", "0"))
    task_count = int(os.getenv("CLOUD_RUN_TASK_COUNT", "1"))

    dataset_root = Path(args.dataset_dir) if args.dataset_dir else None

    logger.info("=" * 70)
    logger.info("   PHASE 7: CLOUD-SCALE 5-WAY COMPARATIVE BENCHMARK RUNNER")
    logger.info("=" * 70)
    logger.info(f"Task Index:   {task_index} / {task_count}")
    logger.info(f"Live LLM:     {args.use_live_llm}")
    logger.info(f"Concurrency:  {args.concurrency}")
    logger.info(f"Dataset Root: {dataset_root or 'Auto-resolved (KaggleHub or local)'}")

    runner = ScaleBenchmarkRunner(
        dataset_root=dataset_root,
        use_live_llm=args.use_live_llm,
        concurrency=args.concurrency,
    )

    report = runner.run_sharded_benchmark(
        task_index=task_index,
        task_count=task_count,
        include_tier_a=True,
        include_candidates=True,
    )

    output_path = ROOT_DIR / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report written to {output_path}")

    # Print summary table
    print("\n" + "=" * 80)
    print("5-WAY COMPARATIVE EVALUATION SUMMARY (With 95% Wilson Score CIs)")
    print("=" * 80)
    print(f"{'System':<40} | {'Exact Acc':<12} | {'False Safe Rate':<16} | {'False Alarm'}")
    print("-" * 80)

    for sys_key, data in report.get("systems", {}).items():
        name = data["name"][:38]
        acc = data["metrics"].get("exact_accuracy", {}).get("percentage", "N/A")
        fnr = data["metrics"].get("false_no_risk_found_rate", {}).get("percentage", "N/A")
        fpr = data["metrics"].get("false_alarm_rate", {}).get("percentage", "N/A")
        print(f"{name:<40} | {acc:<12} | {fnr:<16} | {fpr}")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
