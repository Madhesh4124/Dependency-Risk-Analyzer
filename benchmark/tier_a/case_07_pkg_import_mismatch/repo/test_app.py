from app import parse_config

def test_parse_config():
    res = parse_config("key: value")
    assert res == {"parsed": "key: value"}

