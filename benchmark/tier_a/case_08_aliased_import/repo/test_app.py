from app import record_critical_incident

def test_record_critical_incident():
    res = record_critical_incident("disk full")
    assert res == "FATAL: disk full"

