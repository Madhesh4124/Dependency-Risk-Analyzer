"""Mock dependency http_dispatcher v2.0.0"""
__version__ = "2.0.0"

def send_request(url: str, timeout: int = 30, ssl_context = None) -> str:
    return f"200 OK from {url}"
