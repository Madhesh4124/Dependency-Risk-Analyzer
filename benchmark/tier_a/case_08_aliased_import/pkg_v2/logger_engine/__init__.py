"""Mock dependency logger_engine v2.0.0"""
__version__ = "2.0.0"

# log_fatal removed in v2!

def log_info(msg: str) -> str:
    """Informational log function."""
    return f"INFO: {msg}"

