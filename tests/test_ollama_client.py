from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from core.ollama_client import OllamaClient, OllamaConnectionError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ndjson_lines(*tokens: str, done_on_last: bool = True) -> list[str]:
    """Build a list of NDJSON lines that mimic Ollama's streaming format."""
    lines = []
    for i, token in enumerate(tokens):
        is_last = done_on_last and i == len(tokens) - 1
        lines.append(json.dumps({"response": token, "done": is_last}))
    return lines


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client() -> OllamaClient:
    return OllamaClient(model="llama3", connect_timeout=1.0, read_timeout=5.0)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_analysis_returns_joined_tokens(client: OllamaClient) -> None:
    """Tokens from the stream are concatenated into a single string."""
    lines = _ndjson_lines("Hello", " world", "!")

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = AsyncMock(return_value=aiter(lines))

    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=mock_stream_ctx)

    mock_client_ctx = MagicMock()
    mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=mock_client_ctx):
        result = await client.generate_analysis(
            system_prompt="You are a security expert.",
            context_data="GET /admin HTTP/1.1",
        )

    assert result == "Hello world!"


@pytest.mark.asyncio
async def test_generate_analysis_skips_empty_lines(client: OllamaClient) -> None:
    """Empty lines and lines with no 'response' key are silently skipped."""
    lines = ["", json.dumps({"response": "", "done": False}),
             json.dumps({"response": "ok", "done": True})]

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = AsyncMock(return_value=aiter(lines))

    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=mock_stream_ctx)

    mock_client_ctx = MagicMock()
    mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=mock_client_ctx):
        result = await client.generate_analysis("sys", "ctx")

    assert result == "ok"


# ---------------------------------------------------------------------------
# Error-handling tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_analysis_raises_on_connect_error(client: OllamaClient) -> None:
    """OllamaConnectionError is raised when Ollama is not running."""
    mock_client_ctx = MagicMock()
    mock_client_ctx.__aenter__ = AsyncMock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=mock_client_ctx):
        with pytest.raises(OllamaConnectionError, match="ollama serve"):
            await client.generate_analysis("sys", "ctx")


@pytest.mark.asyncio
async def test_generate_analysis_raises_on_read_timeout(client: OllamaClient) -> None:
    """OllamaConnectionError is raised on read timeout."""
    mock_client_ctx = MagicMock()
    mock_client_ctx.__aenter__ = AsyncMock(
        side_effect=httpx.ReadTimeout("timed out")
    )
    mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=mock_client_ctx):
        with pytest.raises(OllamaConnectionError, match="read_timeout"):
            await client.generate_analysis("sys", "ctx")


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------

def test_default_url_points_to_localhost() -> None:
    c = OllamaClient()
    assert "localhost" in c._url
    assert "11434" in c._url


def test_custom_base_url() -> None:
    c = OllamaClient(base_url="http://127.0.0.1:9999")
    assert "9999" in c._url
    assert "generate" in c._url


def test_model_is_stored() -> None:
    c = OllamaClient(model="mistral")
    assert c.model == "mistral"


# ---------------------------------------------------------------------------
# Async iterator helper (Python 3.10+)
# ---------------------------------------------------------------------------

async def aiter(items):
    for item in items:
        yield item
