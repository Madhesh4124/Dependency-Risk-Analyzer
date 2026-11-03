"""Mock dependency api_client v1.5.0"""
import warnings

__version__ = "1.5.0"

def request_v1(endpoint: str) -> dict:
    """Deprecated request handler emitting DeprecationWarning."""
    warnings.warn(
        "request_v1 is deprecated and will be removed in api-client 2.0.0. Use request() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return {"status": "ok", "endpoint": endpoint, "version": "v1"}

def request(endpoint: str) -> dict:
    """Standard request handler."""
    return {"status": "ok", "endpoint": endpoint, "version": "v2"}

