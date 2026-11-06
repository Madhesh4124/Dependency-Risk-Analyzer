from app import fetch_rows

def test_fetch_rows():
    rows = fetch_rows("SELECT * FROM items")
    assert len(rows) == 2
