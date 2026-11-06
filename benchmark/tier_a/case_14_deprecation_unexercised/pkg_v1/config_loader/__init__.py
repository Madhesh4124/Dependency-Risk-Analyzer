"""Mock dependency config_loader v1.3.0"""
__version__ = "1.3.0"
import json

def load_json(text: str):
    return json.loads(text)

def load_ini(text: str):
    return {"format": "ini"}
