"""Unit tests for Phase 7: Full-Scale Cloud Benchmark components.

Tests:
1. Kaggle dataset loader and candidate filtering
2. 5-way comparative evaluation baselines (SemVer, Green CI, Pure AST)
3. Statistical metrics and Wilson-score confidence intervals
4. Sharded scale benchmark execution runner
"""

from pathlib import Path
import pytest

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
from risk_agent.benchmark.scale_runner import ScaleBenchmarkRunner
from risk_agent.models.schemas import SeverityVerdict


def test_wilson_score_interval_bounds():
    # 0 out of 10
    zero_ci = wilson_score_interval(0, 10)
    assert zero_ci["proportion"] == 0.0
    assert zero_ci["lower"] == 0.0
    assert zero_ci["upper"] > 0.0

    # 10 out of 10
    full_ci = wilson_score_interval(10, 10)
    assert full_ci["proportion"] == 1.0
    assert full_ci["upper"] == 1.0
    assert full_ci["lower"] < 1.0

    # Normal distribution
    ci = wilson_score_interval(50, 100)
    assert ci["proportion"] == 0.5
    assert 0.4 < ci["lower"] < 0.5
    assert 0.5 < ci["upper"] < 0.6


def test_compute_binary_metrics():
    y_true = ["RISKY", "RISKY", "NO_RISK_FOUND", "NO_RISK_FOUND"]
    y_pred = ["RISKY", "NO_RISK_FOUND", "NO_RISK_FOUND", "RISKY"]

    metrics = compute_binary_metrics(y_true, y_pred)
    assert metrics["total_evaluated"] == 4
    assert metrics["confusion_matrix"]["tp"] == 1
    assert metrics["confusion_matrix"]["fn"] == 1  # 1 false negative
    assert metrics["confusion_matrix"]["tn"] == 1
    assert metrics["confusion_matrix"]["fp"] == 1  # 1 false alarm
    assert metrics["exact_accuracy"]["count"] == "2/4"


def test_latency_distribution():
    lats = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    dist = compute_latency_distribution(lats)
    assert dist["min_ms"] == 10.0
    assert dist["max_ms"] == 100.0
    assert dist["mean_ms"] == 55.0
    assert dist["p50_ms"] == 50.0
    assert dist["p95_ms"] == 100.0


def test_semver_baseline():
    b = SemVerBaseline()
    assert b.evaluate("major", "1.0.0", "2.0.0") == SeverityVerdict.RISKY
    assert b.evaluate("minor", "1.0.0", "1.1.0") == SeverityVerdict.NO_RISK_FOUND
    assert b.evaluate("patch", "1.0.0", "1.0.1") == SeverityVerdict.NO_RISK_FOUND


def test_green_ci_baseline():
    b = GreenCIBaseline()
    assert b.evaluate("SUCCESS") == SeverityVerdict.NO_RISK_FOUND
    assert b.evaluate("FAILURE") == SeverityVerdict.RISKY
    assert b.evaluate("UNKNOWN") == SeverityVerdict.RISKY
    assert b.evaluate(None) == SeverityVerdict.RISKY


def test_pure_ast_baseline():
    b = PureASTBaseline()
    # Code that directly calls package
    code_with_usage = {"app.py": "import requests\nresp = requests.get('https://example.com')\n"}
    assert b.evaluate_code("requests", code_with_usage) == SeverityVerdict.RISKY

    # Code that has unused package import
    code_unused = {"app.py": "import requests\nx = 1\n"}
    assert b.evaluate_code("requests", code_unused) == SeverityVerdict.REVIEW

    # Code without package
    code_none = {"app.py": "import os\nx = 1\n"}
    assert b.evaluate_code("requests", code_none) == SeverityVerdict.NO_RISK_FOUND


def test_kaggle_loader_local_data():
    root = resolve_benchmark_root()
    assert root.exists()

    tier_a = load_tier_a(root)
    assert len(tier_a) >= 20

    tier_b = load_tier_b_curated(root)
    assert len(tier_b) >= 30

    candidates = load_all_candidates(root)
    assert len(candidates) >= 140

    filtered = filter_replayable_candidates(candidates)
    assert len(filtered) > 0
    # Every filtered candidate must have single dependency verified
    for c in filtered:
        chk = c["validation_checklist"]
        assert chk["single_dependency_verified"] is True
        assert chk["commit_shas_captured"] is True


def test_scale_benchmark_runner_offline_slice():
    runner = ScaleBenchmarkRunner(concurrency=2, use_live_llm=False)
    # Run a small slice: task index 0 of 10 tasks
    report = runner.run_sharded_benchmark(task_index=0, task_count=10, include_tier_a=True, include_candidates=True)
    assert report["task_index"] == 0
    assert report["task_count"] == 10
    assert report["cases_evaluated"] > 0
    assert "b1_semver" in report["systems"]
    assert "b2_green_ci" in report["systems"]
    assert "s5_hybrid_agent" in report["systems"]
