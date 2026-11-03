from app import format_title

def test_format_title():
    assert format_title("Dashboard") == "**Dashboard**"

