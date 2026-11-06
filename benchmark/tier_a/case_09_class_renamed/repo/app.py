from cache_driver import MemoryCache

def get_user_data(user_id: str) -> str:
    cache = MemoryCache()
    return cache.get(user_id)
