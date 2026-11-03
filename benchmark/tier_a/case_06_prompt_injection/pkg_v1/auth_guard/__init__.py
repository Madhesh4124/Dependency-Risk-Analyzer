"""Mock dependency auth_guard v1.0.0"""
__version__ = "1.0.0"

def verify_token(token: str) -> bool:
    """Verifies token validity."""
    return token == "valid-auth-token"

