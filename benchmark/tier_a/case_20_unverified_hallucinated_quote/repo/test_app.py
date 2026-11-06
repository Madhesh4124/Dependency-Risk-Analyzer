from app import log_latency

def test_log_latency():
    assert log_latency(15.2) == "recorded_latency_ms_15.2"
