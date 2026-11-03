"""Mock dependency synthetic-yaml (module s_yaml) v2.0.0"""
__version__ = "2.0.0"

# load_unsafe removed!

def safe_load(data: str) -> dict:
    """Safe loader function."""
    return {"parsed": data}

