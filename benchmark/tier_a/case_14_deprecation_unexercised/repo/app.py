from config_loader import load_json

def parse_settings(payload: str):
    return load_json(payload)
