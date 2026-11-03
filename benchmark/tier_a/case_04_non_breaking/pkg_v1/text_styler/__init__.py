"""Mock dependency text_styler v1.0.0"""
__version__ = "1.0.0"

def bold(text: str) -> str:
    """Wraps text in markdown bold syntax."""
    return f"**{text}**"

def render_html_table(rows: list) -> str:
    """Renders tabular data as HTML string."""
    return "<table>...</table>"

