from app import parse_settings

def test_parse_settings():
    assert parse_settings('{"ok": true}') == {"ok": True}
