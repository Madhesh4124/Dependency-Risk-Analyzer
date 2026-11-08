"""Statistical significance and evaluation metrics for Phase 7 benchmarking.

Computes:
- Confusion Matrix (TP, FP, TN, FN)
- Precision, Recall, Specificity, F1-Score
- False NO_RISK_FOUND Rate (Catastrophic supply chain miss)
- False Alarm Rate (False Positive Rate)
- 95% Confidence Intervals via Wilson Score Interval
- Latency percentiles (p50, p90, p95)
- Stratification by bump type (MAJOR, MINOR, PATCH) and package ecosystem
"""

import math
from typing import Any, Dict, List, Optional, Tuple


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Dict[str, float]:
    """Calculates Wilson score confidence interval for a binomial proportion.
    
    Robust for small sample sizes and proportions near 0 or 1.
    """
    if total == 0:
        return {"proportion": 0.0, "lower": 0.0, "upper": 0.0, "error_margin": 0.0}

    # Standard normal quantile for confidence level (1.95996 for 95%)
    z = 1.95996 if confidence == 0.95 else 2.576 if confidence == 0.99 else 1.645
    p_hat = successes / total

    denominator = 1 + (z ** 2) / total
    center_adjusted = (p_hat + (z ** 2) / (2 * total)) / denominator
    spread = z * math.sqrt((p_hat * (1 - p_hat) + (z ** 2) / (4 * total)) / total) / denominator

    lower = max(0.0, center_adjusted - spread)
    upper = min(1.0, center_adjusted + spread)

    return {
        "proportion": round(p_hat, 4),
        "lower": round(lower, 4),
        "upper": round(upper, 4),
        "error_margin": round((upper - lower) / 2, 4),
    }


def compute_binary_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Computes binary classification metrics where Positive = RISKY, Negative = NO_RISK_FOUND.
    
    REVIEW is treated as a guarded warning (non-negative).
    """
    total = len(y_true)
    if total == 0:
        return {}

    tp = 0  # True RISKY predicted RISKY or REVIEW
    fn = 0  # True RISKY predicted NO_RISK_FOUND (Catastrophic miss!)
    tn = 0  # True NO_RISK_FOUND predicted NO_RISK_FOUND
    fp = 0  # True NO_RISK_FOUND predicted RISKY (False alarm)

    exact_matches = 0

    for yt, yp in zip(y_true, y_pred):
        yt_norm = yt.upper()
        yp_norm = yp.upper()

        if yt_norm == yp_norm:
            exact_matches += 1

        if yt_norm == "RISKY":
            if yp_norm in ("RISKY", "REVIEW"):
                tp += 1
            else:
                fn += 1
        elif yt_norm == "NO_RISK_FOUND":
            if yp_norm == "NO_RISK_FOUND":
                tn += 1
            else:
                fp += 1

    accuracy_ci = wilson_score_interval(exact_matches, total)
    
    # False Negative Rate (False NO_RISK_FOUND rate on truly risky bumps)
    risky_total = tp + fn
    fnr_ci = wilson_score_interval(fn, risky_total) if risky_total > 0 else {"proportion": 0.0, "lower": 0.0, "upper": 0.0}

    # False Positive Rate (False Alarm rate on truly benign bumps)
    benign_total = tn + fp
    fpr_ci = wilson_score_interval(fp, benign_total) if benign_total > 0 else {"proportion": 0.0, "lower": 0.0, "upper": 0.0}

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "total_evaluated": total,
        "exact_accuracy": {
            "count": f"{exact_matches}/{total}",
            "percentage": f"{accuracy_ci['proportion'] * 100:.1f}%",
            "ci_95": [accuracy_ci["lower"], accuracy_ci["upper"]],
        },
        "false_no_risk_found_rate": {
            "count": f"{fn}/{risky_total}" if risky_total > 0 else "0/0",
            "percentage": f"{fnr_ci['proportion'] * 100:.1f}%",
            "ci_95": [fnr_ci["lower"], fnr_ci["upper"]],
        },
        "false_alarm_rate": {
            "count": f"{fp}/{benign_total}" if benign_total > 0 else "0/0",
            "percentage": f"{fpr_ci['proportion'] * 100:.1f}%",
            "ci_95": [fpr_ci["lower"], fpr_ci["upper"]],
        },
        "confusion_matrix": {
            "tp": tp,
            "fn": fn,
            "tn": tn,
            "fp": fp,
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
    }


def compute_latency_distribution(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates latency statistics across benchmark runs."""
    if not latencies_ms:
        return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}

    sorted_lat = sorted(latencies_ms)
    n = len(sorted_lat)

    def percentile(p: float) -> float:
        idx = int(math.ceil(p * n)) - 1
        return sorted_lat[max(0, min(idx, n - 1))]

    return {
        "p50_ms": round(percentile(0.50), 2),
        "p90_ms": round(percentile(0.90), 2),
        "p95_ms": round(percentile(0.95), 2),
        "mean_ms": round(sum(sorted_lat) / n, 2),
        "min_ms": round(sorted_lat[0], 2),
        "max_ms": round(sorted_lat[-1], 2),
    }
