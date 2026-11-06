"""Mock dependency event_bus v2.0.0"""
__version__ = "2.0.0"

def publish_async(topic: str, msg: str):
    return f"asynced:{topic}:{msg}"
