"""Mock dependency stream_processor v1.0.0"""
__version__ = "1.0.0"

class StreamWorker:
    def flush_buffer(self):
        return "flushed"
