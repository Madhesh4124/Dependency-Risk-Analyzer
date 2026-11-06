"""Mock dependency event_bus v1.0.0"""
__version__ = "1.0.0"

def publish_sync(topic: str, msg: str):
    return f"synced:{topic}:{msg}"

def publish_async(topic: str, msg: str):
    return f"asynced:{topic}:{msg}"
