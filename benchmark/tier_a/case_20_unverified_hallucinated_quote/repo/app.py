from metric_collector import record_metric

def log_latency(ms: float):
    return record_metric("latency_ms", ms)
