from http_dispatcher import send_request

def check_endpoint(url: str) -> str:
    return send_request(url, timeout=5, verify_ssl=False)
