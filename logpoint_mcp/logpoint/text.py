"""Text helpers for Logpoint queries, comments and results."""
from __future__ import annotations

import html
import re
from typing import Any

# The Logpoint web UI double-escapes incident comments, so `"` is displayed as `&#34;`.
# Swap the affected characters for look-alikes so comments read correctly.
_UI_SAFE = {'"': "”", "'": "’", "<": "‹", ">": "›", "&": "+"}

# Columns Logpoint adds to chart results for its own bookkeeping.
_INTERNAL_COLUMN = re.compile(r"^(_type_.*|_group)$")
# Fields Logpoint returns HTML-escaped.
_HTML_ESCAPED_FIELDS = {"command", "parent_command"}

MAX_COMMENT_CHARS = 4000


def search_part(query: str) -> str:
    """The search part of a query: everything before the first `|` that is outside quotes.

    `norm_id=Okta reason="a|b" | chart count() by user` -> `norm_id=Okta reason="a|b"`
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(query):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "|":
            return query[:index].strip()
    return query.strip()


def ui_safe_comment(text: str, prefix: str = "") -> str:
    """Plain text that displays correctly in the Logpoint UI, tagged with `prefix`."""
    for char, replacement in _UI_SAFE.items():
        text = text.replace(char, replacement)
    text = text.strip()
    if not text:
        raise ValueError("The comment is empty.")
    if prefix and not text.startswith(prefix):
        text = f"{prefix} {text}"
    if len(text) > MAX_COMMENT_CHARS:
        text = text[: MAX_COMMENT_CHARS - 1] + "…"
    return text


def clean_row(row: Any, max_chars: int) -> Any:
    """Drop internal columns, unescape HTML-escaped fields and clip long values."""
    if not isinstance(row, dict):
        return row
    cleaned = {}
    for key, value in row.items():
        if _INTERNAL_COLUMN.match(str(key)):
            continue
        if isinstance(value, str):
            if key in _HTML_ESCAPED_FIELDS:
                value = html.unescape(value)
            value = clip(value, max_chars)
        cleaned[key] = value
    return cleaned


def clip(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return f"{value[:max_chars]}… [{len(value) - max_chars} more chars]"


def compact(record: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Drop empty values and clip long strings, to keep tool output small."""
    result = {}
    for key, value in record.items():
        if value is None or value == "" or value == [] or value == {}:
            continue
        result[key] = clip(value, max_chars) if isinstance(value, str) else value
    return result
