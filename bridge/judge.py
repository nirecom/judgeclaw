"""Judge LLM client for semantic PII/safety inspection."""
import json
import os
import re

import httpx

JUDGE_MODEL = os.environ.get("JUDGE_MODEL_NAME", "judge")
JUDGE_TIMEOUT = float(os.environ.get("JUDGE_TIMEOUT", "30"))

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


async def check_with_judge(text: str, litellm_url: str) -> dict:
    """Check text with Judge LLM. Returns {"safe": bool, "reason": str}.

    Fail-closed: returns {"safe": False} on any error.
    """
    # Truncate to fit Judge model context (keep tail — latest user input matters most)
    max_chars = 3000
    if len(text) > max_chars:
        text = text[-max_chars:]

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(JUDGE_TIMEOUT)
        ) as client:
            response = await client.post(
                f"{litellm_url}/v1/chat/completions",
                json={
                    "model": JUDGE_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": text},
                    ],
                    "temperature": 0,
                    "max_tokens": 1000,
                },
            )

        if response.status_code != 200:
            return {"safe": False, "reason": f"Judge HTTP {response.status_code}"}

        data = response.json()
        content = data["choices"][0]["message"]["content"]
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

        # Unparseable → fail-closed
        return {"safe": False, "reason": "Judge response unparseable"}

    except Exception as e:
        return {"safe": False, "reason": f"Judge error: {type(e).__name__}"}
