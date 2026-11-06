from app import get_user_data

def test_get_user_data():
    assert get_user_data("42") == "cached_42"
