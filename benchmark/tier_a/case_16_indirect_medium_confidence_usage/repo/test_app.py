from app import CustomQueue, cleanup_worker

def test_cleanup_worker():
    q = CustomQueue()
    assert cleanup_worker(q) == "internal_queue_flushed"
