from app import retrieve_token

def test_retrieve_token():
    assert retrieve_token() == "secret-value-for-api_token"

