from app import send_event

def test_send_event():
    assert send_event("orders", "paid") == "asynced:orders:paid"
