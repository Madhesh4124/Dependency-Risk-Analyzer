from event_bus import publish_async

def send_event(name: str, payload: str):
    return publish_async(name, payload)
