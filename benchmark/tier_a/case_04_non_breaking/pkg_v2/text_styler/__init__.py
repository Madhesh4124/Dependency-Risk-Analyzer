"""Mock dependency text_styler v2.0.0"""
__version__ = "2.0.0"

def bold(text: str) -> str:
    """Wraps text in markdown bold syntax."""
    return f"**{text}**"

# render_html_table removed in v2.0.0

