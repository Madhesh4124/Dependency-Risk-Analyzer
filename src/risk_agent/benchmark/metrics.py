"""Statistical significance and evaluation metrics for Phase 7 benchmarking.

Computes:
- Confusion Matrix (TP, FP, TN, FN)
- Precision, Recall, Specificity, F1-Score
- False NO_RISK_FOUND Rate (Catastrophic supply chain miss)
- False Alarm Rate (False Positive Rate)
- 95% Confidence Intervals via Wilson Score Interval
- Latency percentiles (p50_ms, p90_ms, p95_ms)
- Distribution breakdowns and abstention rates
"""

from collections import Counter
import math
from typing import Any, Dict, List


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

    REVIEW is treated as a guarded warning (non-negative). Exact-match accuracy counts
    full label agreement across all evaluated labels (including REVIEW).
    """
    total = len(y_true)
    if total == 0:
        return {}

    tp = 0  # True RISKY predicted RISKY or REVIEW
    fn = 0  # True RISKY predicted NO_RISK_FOUND (Catastrophic miss)
    tn = 0  # True NO_RISK_FOUND predicted NO_RISK_FOUND
    fp = 0  # True NO_RISK_FOUND predicted RISKY or REVIEW (False alarm)

    exact_matches = 0
    gt_counter: Counter[str] = Counter()
    pred_counter: Counter[str] = Counter()

    for yt, yp in zip(y_true, y_pred):
        yt_norm = (yt or "UNKNOWN").upper()
        yp_norm = (yp or "UNKNOWN").upper()
        gt_counter[yt_norm] += 1
        pred_counter[yp_norm] += 1

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

    binary_evaluable = risky_total + benign_total
    review_predicted = pred_counter.get("REVIEW", 0)
    rev_ci = wilson_score_interval(review_predicted, total)

    return {
        "total_evaluated": total,
        "binary_evaluable_count": binary_evaluable,
        "non_binary_ground_truth_count": total - binary_evaluable,
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
        "review_abstention_rate": {
            "count": f"{review_predicted}/{total}",
            "percentage": f"{rev_ci['proportion'] * 100:.1f}%",
            "ci_95": [rev_ci["lower"], rev_ci["upper"]],
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
        "ground_truth_distribution": dict(sorted(gt_counter.items())),
        "prediction_distribution": dict(sorted(pred_counter.items())),
    }


def compute_latency_distribution(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates latency statistics in milliseconds across benchmark runs."""
    if not latencies_ms:
        return {"p50_ms": 0.0, "p90_ms": 0.0, "p95_ms": 0.0, "mean_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}

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
