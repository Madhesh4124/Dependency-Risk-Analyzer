"""Mock dependency data_transformer v1.0.0"""
__version__ = "1.0.0"

def transform_legacy(data: str) -> str:
    """Legacy transform function to be removed in v2."""
    return f"legacy:{data}"

def transform(data: str) -> str:
    """Current recommended transform function."""
    return f"modern:{data}"

