"""Mock dependency auth_guard v2.0.0"""
__version__ = "2.0.0"

def verify_token(token: str, secret_key: str) -> bool:
    """Verifies token validity requiring a secret key."""
    return token == "valid-auth-token" and secret_key == "top-secret"

