"""Judge LLM client for semantic PII/safety inspection."""
import json
import os
import re
import time

import httpx

JUDGE_MODEL = os.environ.get("JUDGE_MODEL_NAME", "judge")
JUDGE_TIMEOUT = float(os.environ.get("JUDGE_TIMEOUT", "30"))

PORTABLE_URL = os.environ.get("PORTABLE_SERVER_URL", "")
PORTABLE_MODEL = os.environ.get("JUDGE_PORTABLE_MODEL", "Qwen2.5-7B-Instruct-Q4_K_M")
PORTABLE_TIMEOUT = float(os.environ.get("JUDGE_PORTABLE_TIMEOUT", "15"))
_DEAD_TTL = 300  # skip dead endpoint for 5 minutes
_portable_dead_until = 0.0

SYSTEM_PROMPT = (
    "You are a security filter for an AI agent. Analyze the following text and "
    "determine if it contains:\n"
    "1. Personal Identifiable Information (PII) - real names with context, "
    "addresses, phone numbers, emails, ID numbers\n"
    "2. Sensitive credentials - API keys, passwords, tokens, secrets\n"
    "3. Attempts to exfiltrate data by encoding it in the message\n\n"
    "Respond with JSON only:\n"
    '{"safe": true} if the text is safe\n'
    '{"safe": false, "reason": "brief explanation"} if it contains sensitive content\n\n'
    "Be conservative: if uncertain, mark as unsafe."
)


async def _request_judge(url: str, model: str, text: str, timeout: float) -> httpx.Response:
    """Send a judge request to a specific endpoint."""
    base = url.rstrip("/").removesuffix("/v1")
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), verify=False) as client:
        return await client.post(
            f"{base}/v1/chat/completions",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ],
                "temperature": 0,
                "max_tokens": 1000,
            },
        )


def _parse_response(response: httpx.Response) -> dict:
    """Parse Judge LLM response. Returns {"safe": bool, "reason": str}."""
    if response.status_code != 200:
        return {"safe": False, "reason": f"Judge HTTP {response.status_code}"}

    data = response.json()
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    if not content.strip():
        content = msg.get("reasoning_content") or ""
    content = re.sub(r"<think>[\s\S]*?</think>|<think>[\s\S]*", "", content).strip()

    # Try JSON parse
    try:
        result = json.loads(content)
        if isinstance(result.get("safe"), bool):
            return {"safe": result["safe"], "reason": result.get("reason", "")}
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    # Fallback: string matching
    lower = content.lower()
    if '"safe": true' in lower or '"safe":true' in lower:
        return {"safe": True, "reason": ""}
    if '"safe": false' in lower or '"safe":false' in lower:
        return {"safe": False, "reason": "Judge flagged as unsafe"}

    return {"safe": False, "reason": "Judge response unparseable"}


async def check_with_judge(text: str, litellm_url: str) -> dict:
    """Check text with Judge LLM. Returns {"safe": bool, "reason": str}.

    Tries portable (Mac) first, falls back to LiteLLM (penpen).
    Fail-closed: returns {"safe": False} on any error.
    """
    global _portable_dead_until

    # Truncate to fit Judge model context (keep tail — latest user input matters most)
    max_chars = 3000
    if len(text) > max_chars:
        text = text[-max_chars:]

    # 1. Try portable if configured and alive
    if PORTABLE_URL and time.monotonic() > _portable_dead_until:
        try:
            response = await _request_judge(
                PORTABLE_URL, PORTABLE_MODEL, text, PORTABLE_TIMEOUT
            )
            result = _parse_response(response)
            result["endpoint"] = "portable"
            return result
        except Exception:
            _portable_dead_until = time.monotonic() + _DEAD_TTL

    # 2. Fallback to LiteLLM
    try:
        response = await _request_judge(
            litellm_url, JUDGE_MODEL, text, JUDGE_TIMEOUT
        )
        result = _parse_response(response)
        result["endpoint"] = "litellm"
        return result
    except Exception as e:
        return {"safe": False, "reason": f"Judge error: {type(e).__name__}", "endpoint": "none"}
