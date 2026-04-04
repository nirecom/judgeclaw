"""PII regex patterns for Bridge inspection."""
import re
from typing import Optional

PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email"),
    (re.compile(r"\b0\d{1,4}[-.]?\d{1,4}[-.]?\d{3,4}\b"), "jp_phone"),
    (re.compile(r"(?:sk-|pk_|rk_|AKIA|ghp_|gho_|xai-|anthropic-)[a-zA-Z0-9]{16,}"), "api_key"),
    (re.compile(r"AIzaSy[a-zA-Z0-9_-]{33}"), "google_api_key"),
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "credit_card"),
    (
        re.compile(
            r"(?:東京都|北海道|(?:京都|大阪)府|.{2,3}県).{1,8}[市区町村].{0,12}(?:\d+丁目|\d+番地?|\d+号)"
        ),
        "jp_address",
    ),
    (re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"), "my_number"),
]


def scan(text: str) -> Optional[tuple[str, str]]:
    """Scan text for PII. Returns (matched_text, pattern_name) or None."""
    for pattern, name in PATTERNS:
        match = pattern.search(text)
        if match:
            return (match.group(), name)
    return None
