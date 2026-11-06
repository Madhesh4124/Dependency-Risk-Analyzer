"""Mock dependency cache_driver v1.0.0"""
__version__ = "1.0.0"

class MemoryCache:
    def get(self, key):
        return f"cached_{key}"
