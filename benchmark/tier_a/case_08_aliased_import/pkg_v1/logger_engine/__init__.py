"""Mock dependency logger_engine v1.0.0"""
__version__ = "1.0.0"

def log_fatal(msg: str) -> str:
    """Fatal log function removed in v2."""
    return f"FATAL: {msg}"

def log_info(msg: str) -> str:
    """Informational log function."""
    return f"INFO: {msg}"

