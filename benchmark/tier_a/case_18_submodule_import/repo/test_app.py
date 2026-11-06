from app import get_pos

def test_get_pos():
    assert get_pos("12,56") == (12.34, 56.78)
