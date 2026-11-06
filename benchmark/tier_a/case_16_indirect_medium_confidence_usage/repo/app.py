class CustomQueue:
    def flush_buffer(self):
        return "internal_queue_flushed"

def cleanup_worker(worker):
    return worker.flush_buffer()
