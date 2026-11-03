"""Mock dependency synthetic-yaml (module s_yaml) v1.0.0"""
__version__ = "1.0.0"

def load_unsafe(data: str) -> dict:
    """Unsafe loader function removed in v2."""
    return {"parsed": data}

def safe_load(data: str) -> dict:
    """Safe loader function."""
    return {"parsed": data}

