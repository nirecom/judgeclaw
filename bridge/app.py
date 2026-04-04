"""OpenClaw Bridge - Judge Filter reverse proxy."""
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from pii_patterns import scan as pii_scan
from judge import check_with_judge

logger = logging.getLogger("bridge")

LITELLM_URL = os.environ.get("LITELLM_URL", "http://openclaw-litellm:4000")
LOG_DIR = os.environ.get("LOG_DIR", "/var/log/openclaw")

INSPECTED_PATHS = {"/v1/chat/completions", "/v1/completions"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(timeout=httpx.Timeout(120.0))
    yield
    await app.state.client.aclose()


app = FastAPI(lifespan=lifespan)


def extract_text(body: dict) -> str:
    """Extract text content from LLM request body for inspection."""
    parts = []
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(part.get("text", ""))
    prompt = body.get("prompt", "")
    if isinstance(prompt, str) and prompt:
        parts.append(prompt)
    elif isinstance(prompt, list):
        parts.extend(p for p in prompt if isinstance(p, str))
    return "\n".join(parts)


def log_decision(action: str, reason: str, path: str):
    """Log inspection decision to file and logger."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "reason": reason,
        "path": path,
    }
    logger.info(json.dumps(entry))
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "judge.log"), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.api_route(
    "/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def proxy(request: Request, path: str):
    body_bytes = await request.body()

    # Inspection for LLM endpoints
    if f"/{path}" in INSPECTED_PATHS and request.method == "POST":
        try:
            body = json.loads(body_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}

        text = extract_text(body)

        if text:
            # 1. PII regex scan (fast)
            pii_result = pii_scan(text)
            if pii_result:
                log_decision("BLOCK", f"PII detected: {pii_result[1]}", f"/{path}")
                return Response(
                    status_code=403,
                    content=json.dumps(
                        {"error": f"Blocked: PII detected ({pii_result[1]})"}
                    ),
                    media_type="application/json",
                )

            # 2. Judge LLM check
            judge_result = await check_with_judge(text, LITELLM_URL)
            if not judge_result["safe"]:
                log_decision(
                    "BLOCK", f"Judge: {judge_result['reason']}", f"/{path}"
                )
                return Response(
                    status_code=403,
                    content=json.dumps(
                        {"error": f"Blocked: {judge_result['reason']}"}
                    ),
                    media_type="application/json",
                )

        log_decision("PASS", "clean", f"/{path}")

    # Forward request
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "transfer-encoding", "connection")
    }

    target_url = f"{LITELLM_URL}/{path}"
    client = request.app.state.client

    # Check if streaming
    is_streaming = False
    if body_bytes:
        try:
            is_streaming = json.loads(body_bytes).get("stream", False)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    if is_streaming:
        req = client.build_request(
            method=request.method,
            url=target_url,
            content=body_bytes,
            headers=forward_headers,
        )
        response = await client.send(req, stream=True)

        async def stream_generator():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            finally:
                await response.aclose()

        resp_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower()
            not in ("transfer-encoding", "connection", "content-encoding")
        }
        return StreamingResponse(
            stream_generator(),
            status_code=response.status_code,
            headers=resp_headers,
            media_type=response.headers.get("content-type", "text/event-stream"),
        )
    else:
        response = await client.request(
            method=request.method,
            url=target_url,
            content=body_bytes,
            headers=forward_headers,
        )
        resp_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower()
            not in (
                "transfer-encoding",
                "connection",
                "content-encoding",
                "content-length",
            )
        }
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=resp_headers,
            media_type=response.headers.get("content-type"),
        )
