from app import is_authorized

def test_is_authorized():
    assert is_authorized("valid-auth-token") is True

