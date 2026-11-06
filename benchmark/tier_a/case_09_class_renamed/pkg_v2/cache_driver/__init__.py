"""Mock dependency cache_driver v2.0.0"""
__version__ = "2.0.0"

class InMemoryCache:
    def get(self, key):
        return f"cached_{key}"
