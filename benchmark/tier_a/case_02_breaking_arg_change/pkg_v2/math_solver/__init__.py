"""Mock dependency math_solver v2.0.0"""
__version__ = "2.0.0"

def solve(equation: str, mode: str, precision: int = 2) -> float:
    """Solves equation with required mode ('exact' or 'approximate') and precision."""
    if mode not in ("exact", "approximate"):
        raise ValueError(f"Unknown mode: {mode}")
    return round(42.0, precision)

