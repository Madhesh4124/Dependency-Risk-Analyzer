"""Mock dependency vault_client v0.9.0"""
__version__ = "0.9.0"

def get_secret(key: str) -> str:
    """Retrieves secret string."""
    return f"secret-value-for-{key}"

