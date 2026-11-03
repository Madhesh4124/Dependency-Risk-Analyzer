from math_solver import solve

def compute_metric(raw_expr: str) -> float:
    """Computes formula with custom precision."""
    return solve(raw_expr, precision=4)

