"""Output formats."""
from .console import render as render_console
from .html import render_html
from .machine import render_json, render_markdown, render_sarif

__all__ = ["render_console", "render_html", "render_json", "render_markdown", "render_sarif"]
