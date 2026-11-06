"""Mock dependency http_dispatcher v1.2.0"""
__version__ = "1.2.0"

def send_request(url: str, timeout: int = 30, verify_ssl: bool = True) -> str:
    return f"200 OK from {url} (verify={verify_ssl})"
