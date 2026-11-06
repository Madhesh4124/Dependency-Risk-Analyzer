"""Mock dependency math_toolkit v2.2.0"""
__version__ = "2.2.0"

def compute_mean(numbers: list[float]) -> float:
    return sum(numbers) / len(numbers)

def compute_variance(numbers: list[float]) -> float:
    m = compute_mean(numbers)
    return sum((x - m) ** 2 for x in numbers) / len(numbers)
