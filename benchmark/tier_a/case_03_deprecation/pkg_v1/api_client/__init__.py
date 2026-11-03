"""Mock dependency api_client v1.4.0"""
__version__ = "1.4.0"

def request_v1(endpoint: str) -> dict:
    """Legacy endpoint handler without warnings."""
    return {"status": "ok", "endpoint": endpoint, "version": "v1"}

def request(endpoint: str) -> dict:
    """Standard request handler."""
    return {"status": "ok", "endpoint": endpoint, "version": "v2"}

