from app import secure_token

def test_secure_token():
    assert secure_token("abc") == "hashed_abc"
