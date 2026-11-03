import s_yaml

def parse_config(content: str) -> dict:
    """Parses config using s_yaml module from synthetic-yaml package."""
    return s_yaml.load_unsafe(content)

