from app import run_pipeline

def test_run_pipeline():
    result = run_pipeline("hello")
    assert result == "legacy:hello"

