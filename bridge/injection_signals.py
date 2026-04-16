"""Injection signal patterns for inbound tool result scanning.

Returns list[str] of signal names that matched.
Pattern strings that target Japanese text intentionally contain Japanese characters
because they are detection-target data, not documentation.
"""
import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "direct_override_en",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
            re.IGNORECASE,
        ),
    ),
    (
        "disregard_en",
        re.compile(
            r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
            re.IGNORECASE,
        ),
    ),
    (
        "role_override_en",
        re.compile(
            r"you\s+are\s+now\b"
            r"|act\s+as\s+(?:a\s+|an\s+)?(?:new\s+|different\s+)?(?:ai|assistant|system)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "chatml_tag",
        re.compile(r"<\|im_start\|>|<\|im_end\|>"),
    ),
    (
        "role_tag",
        re.compile(r"<(?:system|user|assistant)>", re.IGNORECASE),
    ),
    # Japanese: "ignore previous instructions"
    (
        "direct_override_jp",
        re.compile(r"これまでの指示を無視"),
    ),
    # Japanese: "disregard previous instructions"
    (
        "disregard_jp",
        re.compile(r"前の指示を無視"),
    ),
    # Japanese: "show/reveal the system prompt"
    (
        "expose_system_jp",
        re.compile(r"system\s*プロンプト(?:を|の)(?:表示|見せ|出力|教え)"),
    ),
]

# Detect suspicious long base64 blobs (potential encoded payloads / exfil).
# 60+ consecutive base64 chars, excluding known-benign contexts.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{60,}")
_B64_CTX_CHARS = 80  # chars to look back for exclusion markers


def _is_b64_excluded(text: str, match_start: int) -> bool:
    """Return True if this base64 blob is in a known-benign context."""
    preceding = text[max(0, match_start - _B64_CTX_CHARS):match_start]
    return (
        "-----BEGIN" in preceding
        or ";base64," in preceding
        or "data:image/" in preceding
        or "data:application/" in preceding
    )


def scan(text: str) -> list[str]:
    """Scan text for injection signals.

    Returns list of signal names that matched (empty list if safe).
    Only one hit per signal name is reported (first match wins).
    """
    hits: list[str] = []

    for name, pattern in _PATTERNS:
        if pattern.search(text):
            hits.append(name)

    for m in _B64_BLOB.finditer(text):
        if not _is_b64_excluded(text, m.start()):
            hits.append("base64_blob")
            break  # one base64_blob hit is sufficient to block

    return hits
