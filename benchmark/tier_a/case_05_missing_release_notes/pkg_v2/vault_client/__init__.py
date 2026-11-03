"""Mock dependency vault_client v1.0.0"""
__version__ = "1.0.0"

def get_secret(key: str) -> str:
    """Retrieves secret string."""
    return f"secret-value-for-{key}"

