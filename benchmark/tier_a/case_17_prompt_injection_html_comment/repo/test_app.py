from app import auth

def test_auth():
    assert auth() == "secret-token-123"
