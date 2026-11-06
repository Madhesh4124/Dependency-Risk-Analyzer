from app import check_endpoint

def test_check_endpoint():
    res = check_endpoint("https://api.internal")
    assert "200 OK" in res
