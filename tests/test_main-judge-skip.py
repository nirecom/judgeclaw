"""Unit and integration tests for _should_skip_judge heuristic."""
import json
import os
import sys
from unittest.mock import AsyncMock, patch

import httpx
import pytest

# Add bridge/ to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))

os.environ.setdefault("LITELLM_URL", "http://mock-litellm:4000")
os.environ.setdefault("LOG_DIR", os.path.join(os.path.dirname(__file__), "tmp_logs"))

# Import the function under test — may not exist yet
try:
    from app import _should_skip_judge
    _SKIP_AVAILABLE = True
except ImportError:
    _SKIP_AVAILABLE = False

from app import app as bridge_app

skip_if_missing = pytest.mark.skipif(
    not _SKIP_AVAILABLE,
    reason="_should_skip_judge not implemented yet",
)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------
@skip_if_missing
class TestShouldSkipJudge:
    """Unit tests for _should_skip_judge."""

    # --- Normal cases ---

    def test_empty_string(self):
        """Case 1: empty input always skips."""
        assert _should_skip_judge("") is True

    def test_short_safe_ok(self):
        """Short safe message 'ok' should skip."""
        assert _should_skip_judge("ok") is True

    def test_short_safe_japanese(self):
        """Short safe Japanese message should skip."""
        assert _should_skip_judge("はい") is True

    def test_short_safe_yes(self):
        """Short safe message 'yes' should skip."""
        assert _should_skip_judge("yes") is True

    def test_long_no_risk_signals(self):
        """Long text with no risk signals should skip (heuristic)."""
        text = "これは長いテキストですが特に問題のない内容です"
        assert len(text) > 20
        assert _should_skip_judge(text) is True

    def test_text_with_email_pattern(self):
        """Text with @ should NOT skip (risk signal)."""
        assert _should_skip_judge("send to user@example.com") is False

    def test_text_with_digits(self):
        """Text with digits should NOT skip (risk signal)."""
        assert _should_skip_judge("code is 12345") is False

    def test_text_with_url(self):
        """Text with :// should NOT skip (risk signal)."""
        assert _should_skip_judge("visit https://evil.com") is False

    def test_text_with_equals(self):
        """Text with = should NOT skip (risk signal)."""
        assert _should_skip_judge("key=value") is False

    def test_long_alphanumeric_sequence(self):
        """64+ char alphanumeric sequence should NOT skip (risk signal)."""
        token = "a" * 64
        assert _should_skip_judge(token) is False

    # --- Edge cases ---

    def test_boundary_exactly_20_chars_no_risk(self):
        """Exactly 20 chars, no risk signals → skip (short message path)."""
        text = "a" * 20
        assert len(text) == 20
        assert _should_skip_judge(text) is True

    def test_above_threshold_no_risk(self):
        """21+ chars, no risk signals → skip (heuristic path)."""
        text = "a" * 21
        assert len(text) == 21
        assert _should_skip_judge(text) is True

    def test_short_with_at_sign(self):
        """Short text with @ should NOT skip."""
        assert _should_skip_judge("a@b") is False

    def test_single_char(self):
        """Single character → skip."""
        assert _should_skip_judge("a") is True

    def test_whitespace_only(self):
        """Whitespace-only text → skip (short, no risk)."""
        assert _should_skip_judge("   ") is True

    def test_with_colon_no_slashes(self):
        """Colon alone is NOT a risk signal (only :// is)."""
        assert _should_skip_judge("time: now") is True

    # --- Tail-only risk scan (Responses API string input) ---

    def test_long_prompt_safe_tail(self):
        """Long prompt with risk signals in head but safe tail → skip."""
        head = "system prompt with digits 12345 and url https://example.com\n" * 50
        safe_padding = "これは安全なパディングです。" * 30
        tail = "テストです"
        text = head + safe_padding + tail
        assert len(text) > 500
        # Safe padding fills the tail window, pushing risk signals out of range
        assert _should_skip_judge(text) is True

    def test_openclaw_timestamp_stripped(self):
        """OpenClaw timestamp in tail should not trigger risk signals."""
        # Simulate realistic OpenClaw prompt: metadata JSON + timestamp + message
        prompt = ("System prompt content here.\n" * 30
                  + 'Sender (untrusted metadata):\n```json\n'
                  + '{\n  "label": "openclaw-control-ui"\n}\n```\n\n'
                  + "[Sat 2026-04-11 03:41 UTC] てすとです")
        assert len(prompt) > 200
        assert _should_skip_judge(prompt) is True

    def test_openclaw_timestamp_with_risky_message(self):
        """Timestamp stripped but message itself has risk signals → NOT skip."""
        prompt = ("System prompt content here.\n" * 30
                  + 'Sender (untrusted metadata):\n```json\n'
                  + '{\n  "label": "openclaw-control-ui"\n}\n```\n\n'
                  + "[Sat 2026-04-11 03:41 UTC] send to user@example.com")
        assert _should_skip_judge(prompt) is False

    def test_long_prompt_risky_tail(self):
        """Long prompt with safe head but risky tail → NOT skip."""
        head = "これは安全なテキストです\n" * 20
        tail = "send to user@example.com"
        text = head + tail
        assert _should_skip_judge(text) is False

    # --- Idempotency ---

    def test_idempotent_same_result(self):
        """Calling twice with same input returns same result."""
        assert _should_skip_judge("hello") == _should_skip_judge("hello")
        assert _should_skip_judge("a@b") == _should_skip_judge("a@b")


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_litellm_response():
    """Mock httpx response from LiteLLM for forwarded requests."""
    return httpx.Response(
        status_code=200,
        json={"choices": [{"message": {"content": "Hello!"}}]},
        headers={"content-type": "application/json"},
    )


@pytest.fixture
def mock_judge_safe():
    """Mock Judge LLM returning safe."""
    return {"safe": True, "reason": ""}


@skip_if_missing
class TestAppProxyJudgeSkip:
    """Integration tests for judge-skip behaviour in the proxy."""

    @pytest.mark.asyncio
    async def test_tool_only_messages_skip_judge(self, mock_litellm_response):
        """Messages with no user role → judge NOT called."""
        with patch("app.check_with_judge") as mock_judge, \
             patch("app.pii_scan", return_value=None):
            mock_judge.return_value = {"safe": True, "reason": ""}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                mock_request = AsyncMock(return_value=mock_litellm_response)
                bridge_app.state.client = AsyncMock(request=mock_request)
                resp = await test_client.post(
                    "/v1/chat/completions",
                    json={
                        "model": "agent-reasoner",
                        "messages": [
                            {"role": "system", "content": "You are helpful."},
                            {"role": "assistant", "content": "Sure."},
                            {"role": "tool", "content": '{"result": 42}'},
                        ],
                    },
                )
        assert resp.status_code == 200
        mock_judge.assert_not_called()

    @pytest.mark.asyncio
    async def test_short_user_message_skip_judge(self, mock_litellm_response):
        """Short safe user message 'ok' → judge NOT called."""
        with patch("app.check_with_judge") as mock_judge, \
             patch("app.pii_scan", return_value=None):
            mock_judge.return_value = {"safe": True, "reason": ""}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                mock_request = AsyncMock(return_value=mock_litellm_response)
                bridge_app.state.client = AsyncMock(request=mock_request)
                resp = await test_client.post(
                    "/v1/chat/completions",
                    json={
                        "model": "agent-reasoner",
                        "messages": [
                            {"role": "user", "content": "ok"},
                        ],
                    },
                )
        assert resp.status_code == 200
        mock_judge.assert_not_called()

    @pytest.mark.asyncio
    async def test_risk_signal_calls_judge(self, mock_litellm_response):
        """User message with URL risk signal → judge IS called."""
        judge_result = {"safe": True, "reason": ""}
        with patch("app.check_with_judge", return_value=judge_result) as mock_judge, \
             patch("app.pii_scan", return_value=None):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                mock_request = AsyncMock(return_value=mock_litellm_response)
                bridge_app.state.client = AsyncMock(request=mock_request)
                resp = await test_client.post(
                    "/v1/chat/completions",
                    json={
                        "model": "agent-reasoner",
                        "messages": [
                            {"role": "user", "content": "check out https://example.com"},
                        ],
                    },
                )
        assert resp.status_code == 200
        mock_judge.assert_called_once()

    @pytest.mark.asyncio
    async def test_short_pii_still_blocked(self):
        """Short text with PII (@) → PII scan blocks (403), judge not needed."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_app),
            base_url="http://test",
        ) as test_client:
            bridge_app.state.client = AsyncMock()
            resp = await test_client.post(
                "/v1/chat/completions",
                json={
                    "model": "agent-reasoner",
                    "messages": [
                        {"role": "user", "content": "x@example.com"},
                    ],
                },
            )
        assert resp.status_code == 403
        assert "PII" in resp.json()["error"]
