import warnings
from app import fetch_status

def test_fetch_status():
    with warnings.catch_warnings(record=True) as recorded_warnings:
        warnings.simplefilter("always")
        res = fetch_status()
        assert res["status"] == "ok"
        deprecations = [
            w for w in recorded_warnings if issubclass(w.category, DeprecationWarning)
        ]
        # Fails if any DeprecationWarning was emitted
        assert len(deprecations) == 0, f"Expected 0 deprecation warnings, got: {deprecations}"

