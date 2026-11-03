from api_client import request_v1

def fetch_status() -> dict:
    """Fetches status using deprecated endpoint function."""
    return request_v1("/status")

