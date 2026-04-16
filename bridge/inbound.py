"""Inbound tool-result injection filter for openclaw-bridge."""
import hashlib
import logging
import os
import re
import time
from collections import OrderedDict

from injection_signals import scan as _signal_scan
from judge import check_inbound_injection

logger = logging.getLogger("bridge.inbound")

LITELLM_URL = os.environ.get("LITELLM_URL", "http://openclaw-litellm:4000")
INBOUND_ENABLED = os.environ.get("INBOUND_ENABLED", "true").lower() != "false"
INBOUND_JUDGE_MODE = os.environ.get("INBOUND_JUDGE_MODE", "signal+judge")
INBOUND_MIN_CHARS = int(os.environ.get("INBOUND_MIN_CHARS", "30"))
INBOUND_CACHE_TTL = int(os.environ.get("INBOUND_CACHE_TTL", "600"))
INBOUND_CACHE_MAX = int(os.environ.get("INBOUND_CACHE_MAX", "1024"))

_WS = re.compile(r"\s+")
# openclaw compaction marker — not real tool output, never injection
_COMPACTED = re.compile(r"\[compacted:[^\]]*\]")


def _normalize(text: str) -> str:
    return _WS.sub(" ", text).strip()


def _hash(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode()).hexdigest()[:32]


class _JudgeCache:
    """LRU cache for inbound judge PASS results with TTL.

    Only PASS results are cached. BLOCK and errors are never stored.
    Key: sha256[:32] of whitespace-normalised text.
    """

    def __init__(self) -> None:
        self._store: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def get(self, text: str) -> dict | None:
        key = _hash(text)
        if key not in self._store:
            return None
        expires_at, result = self._store[key]
        if INBOUND_CACHE_TTL > 0 and time.monotonic() > expires_at:
            del self._store[key]
            return None
        self._store.move_to_end(key)
        return result

    def set(self, text: str, result: dict) -> None:
        if INBOUND_CACHE_TTL <= 0:
            return  # TTL=0 means no caching
        key = _hash(text)
        expires_at = time.monotonic() + INBOUND_CACHE_TTL
        self._store[key] = (expires_at, result)
        self._store.move_to_end(key)
        while len(self._store) > INBOUND_CACHE_MAX:
            self._store.popitem(last=False)


_cache = _JudgeCache()


def _extract_output(output) -> str:
    """Convert a tool output field (str/list/dict/other) to plain text."""
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        parts = []
        for item in output:
            if isinstance(item, dict):
                for key in ("text", "content", "output"):
                    if key in item:
                        parts.append(str(item[key]))
                        break
        return "\n".join(parts)
    if isinstance(output, dict):
        for key in ("text", "content", "output"):
            if key in output:
                return str(output[key])
    try:
        return str(output)
    except Exception:
        return ""


def extract_tool_results(body: dict) -> list[str]:
    """Extract tool result strings from a Responses API or Chat API body.

    Responses API: input list items with type=function_call_output.
    Chat API: messages with role=tool.
    Standalone output field: fallback for other API variants.
    """
    results: list[str] = []

    # Responses API: input list with function_call_output items
    inp = body.get("input")
    if isinstance(inp, list):
        for item in inp:
            if isinstance(item, dict) and item.get("type") == "function_call_output":
                try:
                    results.append(_extract_output(item.get("output", "")))
                except Exception:
                    pass

    # Chat API: messages with role=tool
    messages = body.get("messages", [])
    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "tool":
                try:
                    results.append(_extract_output(msg.get("content", "")))
                except Exception:
                    pass

    # Standalone output field (some API variants)
    if not results:
        output = body.get("output")
        if output is not None:
            extracted = _extract_output(output)
            if extracted:
                results.append(extracted)

    return [r for r in results if r]  # filter empty strings


async def check_inbound(
    body: dict,
    litellm_url: str | None = None,
    correlation_id: str = "",
) -> dict:
    """Check inbound tool results for prompt injection signals.

    Gate order:
      0. INBOUND_ENABLED=false        → PASS via=disabled
      1. no tool results              → PASS via=empty
      2. injection_signals.scan hit   → BLOCK via=signal:<name>
      3. len < INBOUND_MIN_CHARS      → PASS via=len-skip
      4. INBOUND_JUDGE_MODE=signal-only → PASS via=signal-only
      5. dedup cache hit              → PASS via=dedup
      6. check_inbound_injection call → BLOCK via=judge (fail-closed on error)
      7. cache PASS                   → PASS via=clean

    Returns {"action": "PASS"|"BLOCK", "via": str, "reason": str, "direction": "inbound"}
    """
    url = litellm_url or LITELLM_URL

    # Gate 0: disabled
    if not INBOUND_ENABLED:
        return {"action": "PASS", "via": "disabled", "reason": "", "direction": "inbound"}

    # Gate 1: no tool results
    tool_results = extract_tool_results(body)
    if not tool_results:
        return {"action": "PASS", "via": "empty", "reason": "", "direction": "inbound"}

    text = "\n---\n".join(tool_results)

    # Gate 1b: strip compaction markers; if nothing real remains, pass
    # Also strip the ---  separators that are left behind after removal.
    text_without_compacted = _COMPACTED.sub("", text)
    text_without_compacted = re.sub(r"(\n---\n|^---$)", "", text_without_compacted, flags=re.MULTILINE).strip()
    if not text_without_compacted:
        return {"action": "PASS", "via": "compacted", "reason": "", "direction": "inbound"}
    # Use stripped text for remaining gates so compaction markers don't confuse Judge
    text = text_without_compacted

    # Gate 2: signal scan (full text, no length limit)
    hits = _signal_scan(text)
    if hits:
        signal_name = hits[0]
        return {
            "action": "BLOCK",
            "via": f"signal:{signal_name}",
            "reason": f"Injection signal detected: {signal_name}",
            "direction": "inbound",
        }

    # Gate 3: min chars threshold
    if len(text) < INBOUND_MIN_CHARS:
        return {"action": "PASS", "via": "len-skip", "reason": "", "direction": "inbound"}

    # Gate 4: signal-only mode
    if INBOUND_JUDGE_MODE == "signal-only":
        return {"action": "PASS", "via": "signal-only", "reason": "", "direction": "inbound"}

    # Gate 5: dedup cache (PASS results only)
    cached = _cache.get(text)
    if cached is not None:
        return {"action": "PASS", "via": "dedup", "reason": "", "direction": "inbound"}

    # Gate 6: judge LLM (fail-closed)
    try:
        judge_input = text[:4000]
        result = await check_inbound_injection(judge_input, url)
        if not result.get("safe", False):
            logger.warning(
                "inbound BLOCK cid=%s content_preview=%r",
                correlation_id,
                judge_input[:300],
            )
            return {
                "action": "BLOCK",
                "via": "judge",
                "reason": result.get("reason", "Judge flagged as unsafe"),
                "direction": "inbound",
            }
    except Exception as exc:
        logger.warning("check_inbound judge error: %s", exc)
        return {
            "action": "BLOCK",
            "via": "judge",
            "reason": f"Judge error: {type(exc).__name__}",
            "direction": "inbound",
        }

    # Gate 7: cache PASS and return clean
    _cache.set(text, {"safe": True})
    return {"action": "PASS", "via": "clean", "reason": "", "direction": "inbound"}
