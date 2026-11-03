"""Mock dependency data_transformer v2.0.0"""
__version__ = "2.0.0"

# transform_legacy has been removed!

def transform(data: str) -> str:
    """Current recommended transform function."""
    return f"modern:{data}"

