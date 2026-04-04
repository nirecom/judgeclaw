"""Phase 2 Bridge (Judge Filter) unit tests."""
import json
import os
import sys
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio

# Add bridge/ to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bridge"))

os.environ.setdefault("LITELLM_URL", "http://mock-litellm:4000")
os.environ.setdefault("LOG_DIR", os.path.join(os.path.dirname(__file__), "tmp_logs"))

from pii_patterns import scan
from judge import check_with_judge


# ---------------------------------------------------------------------------
# PII Patterns
# ---------------------------------------------------------------------------
class TestPIIPatterns:
    """PII regex scan tests."""

    # --- Normal: no PII ---
    def test_clean_text(self):
        assert scan("meeting notes for next week") is None

    def test_empty_string(self):
        assert scan("") is None

    def test_code_snippet(self):
        assert scan("for i in range(10): print(i)") is None

    # --- Error: PII detected ---
    def test_email(self):
        result = scan("send to user@example.com please")
        assert result is not None
        assert result[1] == "email"

    def test_api_key_sk(self):
        result = scan("key is sk-abcdefghij1234567890abcd")
        assert result is not None
        assert result[1] == "api_key"

    def test_api_key_ghp(self):
        result = scan("token ghp_abcdefghij1234567890abcd")
        assert result is not None
        assert result[1] == "api_key"

    def test_api_key_akia(self):
        result = scan("aws AKIA1234567890ABCDEFGH")
        assert result is not None
        assert result[1] == "api_key"

    def test_api_key_xai(self):
        result = scan("token xai-abcdefghij1234567890")
        assert result is not None
        assert result[1] == "api_key"

    def test_api_key_anthropic(self):
        result = scan("key anthropic-abcdefghij1234567890")
        assert result is not None
        assert result[1] == "api_key"

    def test_google_api_key(self):
        result = scan("key AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q")
        assert result is not None
        assert result[1] == "google_api_key"

    def test_jp_phone_mobile(self):
        result = scan("call 090-1234-5678")
        assert result is not None
        assert result[1] == "jp_phone"

    def test_jp_phone_landline(self):
        result = scan("tel: 03-1234-5678")
        assert result is not None
        assert result[1] == "jp_phone"

    def test_credit_card(self):
        result = scan("card 4111-1111-1111-1111")
        assert result is not None
        assert result[1] == "credit_card"

    def test_jp_address(self):
        result = scan("住所は東京都千代田区です")
        assert result is not None
        assert result[1] == "jp_address"

    def test_jp_address_prefecture(self):
        result = scan("神奈川県横浜市に住んでいます")
        assert result is not None
        assert result[1] == "jp_address"

    def test_my_number(self):
        result = scan("番号は 1234 5678 9012")
        assert result is not None
        assert result[1] == "my_number"

    # --- Edge: similar but not PII ---
    def test_domain_not_email(self):
        assert scan("visit example.com for details") is None

    def test_short_number_not_phone(self):
        assert scan("code 1234") is None

    def test_url_not_pii(self):
        assert scan("see https://docs.python.org/3/library/") is None

    def test_four_digit_year_not_pii(self):
        assert scan("in the year 2025") is None


# ---------------------------------------------------------------------------
# Judge LLM client
# ---------------------------------------------------------------------------
def _mock_judge_response(content: str, status_code: int = 200) -> httpx.Response:
    """Build a mock httpx.Response for Judge LLM."""
    if status_code != 200:
        return httpx.Response(status_code=status_code, json={"error": "bad"})
    return httpx.Response(
        status_code=200,
        json={
            "choices": [{"message": {"content": content}}],
        },
    )


class TestJudge:
    """Judge LLM client tests."""

    @pytest.mark.asyncio
    async def test_safe_response(self):
        mock_post = AsyncMock(
            return_value=_mock_judge_response('{"safe": true}')
        )
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("hello world", "http://mock:4000")
        assert result["safe"] is True

    @pytest.mark.asyncio
    async def test_unsafe_response(self):
        mock_post = AsyncMock(
            return_value=_mock_judge_response(
                '{"safe": false, "reason": "contains PII"}'
            )
        )
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("user@example.com", "http://mock:4000")
        assert result["safe"] is False
        assert "PII" in result["reason"]

    @pytest.mark.asyncio
    async def test_http_error_returns_unsafe(self):
        mock_post = AsyncMock(
            return_value=_mock_judge_response("", status_code=500)
        )
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("test", "http://mock:4000")
        assert result["safe"] is False

    @pytest.mark.asyncio
    async def test_connection_error_returns_unsafe(self):
        mock_post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("test", "http://mock:4000")
        assert result["safe"] is False
        assert "ConnectError" in result["reason"]

    @pytest.mark.asyncio
    async def test_unparseable_json_returns_unsafe(self):
        mock_post = AsyncMock(
            return_value=_mock_judge_response("I think this is fine")
        )
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("test", "http://mock:4000")
        assert result["safe"] is False
        assert "unparseable" in result["reason"]

    @pytest.mark.asyncio
    async def test_fallback_string_match_safe(self):
        mock_post = AsyncMock(
            return_value=_mock_judge_response(
                'Based on analysis: {"safe": true} - no issues'
            )
        )
        with patch("judge.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=AsyncMock(post=mock_post)
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await check_with_judge("test", "http://mock:4000")
        assert result["safe"] is True


# ---------------------------------------------------------------------------
# App integration (FastAPI proxy)
# ---------------------------------------------------------------------------
from app import app as bridge_app, extract_text


class TestExtractText:
    """extract_text helper tests."""

    def test_chat_messages(self):
        body = {"messages": [{"role": "user", "content": "hello world"}]}
        assert "hello world" in extract_text(body)

    def test_multipart_content(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe this"},
                        {"type": "image_url", "url": "http://img"},
                    ],
                }
            ]
        }
        assert "describe this" in extract_text(body)

    def test_prompt_field(self):
        body = {"prompt": "complete this sentence"}
        assert "complete this sentence" in extract_text(body)

    def test_responses_api_string_input(self):
        body = {"input": "what is the weather?"}
        assert "what is the weather?" in extract_text(body)

    def test_responses_api_message_array_input(self):
        body = {"input": [{"role": "user", "content": "hello from responses api"}]}
        assert "hello from responses api" in extract_text(body)

    def test_responses_api_multipart_input(self):
        body = {
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "describe"}],
                }
            ]
        }
        assert "describe" in extract_text(body)

    def test_empty_body(self):
        assert extract_text({}) == ""


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


@pytest.fixture
def mock_judge_unsafe():
    """Mock Judge LLM returning unsafe."""
    return {"safe": False, "reason": "sensitive content detected"}


class TestAppProxy:
    """App-level proxy integration tests."""

    @pytest.mark.asyncio
    async def test_health(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_clean_request_passes(
        self, mock_litellm_response, mock_judge_safe
    ):
        with patch("app.check_with_judge", return_value=mock_judge_safe), patch(
            "app.pii_scan", return_value=None
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                # Mock the forwarding client
                mock_request = AsyncMock(return_value=mock_litellm_response)
                bridge_app.state.client = AsyncMock(request=mock_request)

                resp = await test_client.post(
                    "/v1/chat/completions",
                    json={
                        "model": "agent-reasoner",
                        "messages": [
                            {"role": "user", "content": "what is 2+2?"}
                        ],
                    },
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_pii_email_blocked(self):
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
                        {
                            "role": "user",
                            "content": "send email to user@example.com",
                        }
                    ],
                },
            )
        assert resp.status_code == 403
        assert "PII" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_pii_apikey_blocked(self):
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
                        {
                            "role": "user",
                            "content": "my key is sk-abcdefghij1234567890abcd",
                        }
                    ],
                },
            )
        assert resp.status_code == 403
        assert "api_key" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_judge_unsafe_blocked(
        self, mock_judge_unsafe
    ):
        with patch("app.pii_scan", return_value=None), patch(
            "app.check_with_judge", return_value=mock_judge_unsafe
        ):
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
                            {
                                "role": "user",
                                "content": "tell me about the secret project",
                            }
                        ],
                    },
                )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_judge_error_blocked(self):
        judge_error = {"safe": False, "reason": "Judge error: ConnectError"}
        with patch("app.pii_scan", return_value=None), patch(
            "app.check_with_judge", return_value=judge_error
        ):
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
                            {"role": "user", "content": "hello"}
                        ],
                    },
                )
        assert resp.status_code == 403
        assert "Judge" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_empty_body_forwarded(self, mock_litellm_response):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_app),
            base_url="http://test",
        ) as test_client:
            mock_request = AsyncMock(return_value=mock_litellm_response)
            bridge_app.state.client = AsyncMock(request=mock_request)
            resp = await test_client.get("/v1/models")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_responses_api_clean_passes(
        self, mock_litellm_response, mock_judge_safe
    ):
        """POST /v1/responses must be inspected like /v1/chat/completions."""
        with patch("app.check_with_judge", return_value=mock_judge_safe), patch(
            "app.pii_scan", return_value=None
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                mock_request = AsyncMock(return_value=mock_litellm_response)
                bridge_app.state.client = AsyncMock(request=mock_request)
                resp = await test_client.post(
                    "/v1/responses",
                    json={"model": "agent-reasoner", "input": "what is 2+2?"},
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_responses_api_pii_blocked(self):
        """PII in /v1/responses input must be blocked."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_app),
            base_url="http://test",
        ) as test_client:
            bridge_app.state.client = AsyncMock()
            resp = await test_client.post(
                "/v1/responses",
                json={
                    "model": "agent-reasoner",
                    "input": "send to user@example.com",
                },
            )
        assert resp.status_code == 403
        assert "PII" in resp.json()["error"]

    @pytest.mark.asyncio
    async def test_responses_api_judge_blocked(self, mock_judge_unsafe):
        """Judge-flagged /v1/responses must be blocked."""
        with patch("app.pii_scan", return_value=None), patch(
            "app.check_with_judge", return_value=mock_judge_unsafe
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://test",
            ) as test_client:
                bridge_app.state.client = AsyncMock()
                resp = await test_client.post(
                    "/v1/responses",
                    json={
                        "model": "agent-reasoner",
                        "input": [
                            {"role": "user", "content": "secret project details"}
                        ],
                    },
                )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_non_inspected_path_forwarded(self, mock_litellm_response):
        """Paths outside INSPECTED_PATHS are forwarded without inspection."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=bridge_app),
            base_url="http://test",
        ) as test_client:
            mock_request = AsyncMock(return_value=mock_litellm_response)
            bridge_app.state.client = AsyncMock(request=mock_request)
            resp = await test_client.get("/v1/models")
        assert resp.status_code == 200
        mock_request.assert_called_once()
