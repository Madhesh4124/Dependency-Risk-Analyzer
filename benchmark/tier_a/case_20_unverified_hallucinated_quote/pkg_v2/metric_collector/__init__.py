"""Mock dependency metric_collector v1.5.0"""
__version__ = "1.5.0"

def record_metric(name: str, val: float):
    return f"recorded_{name}_{val}"
