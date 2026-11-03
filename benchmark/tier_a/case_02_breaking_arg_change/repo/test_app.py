from app import compute_metric

def test_compute_metric():
    val = compute_metric("2 + 2")
    assert val == 42.0

