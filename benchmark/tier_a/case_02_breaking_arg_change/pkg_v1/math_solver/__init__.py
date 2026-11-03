"""Mock dependency math_solver v1.1.0"""
__version__ = "1.1.0"

def solve(equation: str, precision: int = 2) -> float:
    """Solves equation with optional precision."""
    return round(42.0, precision)

