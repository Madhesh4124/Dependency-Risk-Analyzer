"""Mock dependency math_toolkit v2.1.0"""
__version__ = "2.1.0"

def compute_mean(numbers: list[float]) -> float:
    return sum(numbers) / len(numbers)
