from __future__ import annotations

import html
import re
from urllib.parse import unquote_plus

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")


def normalize_input(value: str) -> str:
    """Normalize attacker-controlled input for consistent rule matching."""

    decoded = value
    for _ in range(3):
        previous = decoded
        decoded = unquote_plus(html.unescape(decoded))
        if decoded == previous:
            break

    decoded = _CONTROL_CHARS.sub("", decoded)
    decoded = _WHITESPACE.sub(" ", decoded)
    return decoded.strip().lower()
