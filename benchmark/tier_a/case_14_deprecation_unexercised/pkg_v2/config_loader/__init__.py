"""Mock dependency config_loader v1.4.0"""
__version__ = "1.4.0"
import json
import warnings

def load_json(text: str):
    return json.loads(text)

def load_ini(text: str):
    warnings.warn("load_ini is deprecated", DeprecationWarning, stacklevel=2)
    return {"format": "ini"}
