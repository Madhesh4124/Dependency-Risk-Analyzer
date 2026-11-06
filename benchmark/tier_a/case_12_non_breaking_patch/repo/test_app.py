from app import process_title

def test_process_title():
    assert process_title(" hello ") == "HELLO"
