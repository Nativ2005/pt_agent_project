from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

_DEFAULT_BASE_URL = "http://localhost:11434"
_GENERATE_PATH = "/api/generate"
_DEFAULT_MODEL = "llama3"
_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 600.0  # 10 min — llama3 cold-start on CPU can be slow


class OllamaConnectionError(RuntimeError):
    """Raised when the local Ollama daemon is unreachable."""


class OllamaClient:
    """Async HTTP client for the local Ollama inference API.

    Strictly offline — every request goes to localhost only.
    """

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        connect_timeout: float = _CONNECT_TIMEOUT,
        read_timeout: float = _READ_TIMEOUT,
    ) -> None:
        self.model = model
        self._url = base_url.rstrip("/") + _GENERATE_PATH
        self._timeout = httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=30.0,
            pool=5.0,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_analysis(
        self,
        system_prompt: str,
        context_data: str,
    ) -> str:
        """Send a prompt to Ollama and return the full response text.

        Args:
            system_prompt: Role / instruction for the model.
            context_data:  The serialised PT findings to analyse.

        Returns:
            The model's response as a plain string.

        Raises:
            OllamaConnectionError: If Ollama is not running on localhost.
        """
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": context_data,
            "stream": True,
            "options": {"temperature": 0.1},
        }

        try:
            chunks: list[str] = []
            async for chunk in self._stream(payload):
                chunks.append(chunk)
            return "".join(chunks)
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(
                f"Cannot reach Ollama at {self._url}. "
                "Make sure `ollama serve` is running."
            ) from exc
        except httpx.ReadTimeout as exc:
            raise OllamaConnectionError(
                f"Ollama did not respond within {self._timeout.read}s. "
                "Try a smaller model or increase read_timeout."
            ) from exc

    async def ping(self) -> dict[str, str]:
        """Check that Ollama is reachable and return its version info.

        Uses the lightweight /api/version endpoint — no model is loaded.

        Returns:
            Dict with at least a "version" key, e.g. {"version": "0.1.32"}.

        Raises:
            OllamaConnectionError: If Ollama is not running on localhost.
        """
        version_url = self._url.replace(_GENERATE_PATH, "/api/version")
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(version_url)
                response.raise_for_status()
                return response.json()
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(
                f"Cannot reach Ollama at {version_url}. "
                "Make sure `ollama serve` is running."
            ) from exc

    async def list_models(self) -> list[str]:
        """Return the names of locally available Ollama models."""
        tags_url = self._url.replace(_GENERATE_PATH, "/api/tags")
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(tags_url)
                response.raise_for_status()
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(
                "Cannot reach Ollama to list models."
            ) from exc

    async def generate_analysis_stream(
        self,
        system_prompt: str,
        context_data: str,
    ) -> AsyncIterator[str]:
        """Like generate_analysis but yields tokens as they arrive.

        Use this when you want to stream output to the console in real time
        rather than waiting for the full response.

        Raises:
            OllamaConnectionError: If Ollama is not running or times out.
        """
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": context_data,
            "stream": True,
            "options": {"temperature": 0.1},
        }
        try:
            async for token in self._stream(payload):
                yield token
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(
                f"Cannot reach Ollama at {self._url}. "
                "Make sure `ollama serve` is running."
            ) from exc
        except httpx.ReadTimeout as exc:
            raise OllamaConnectionError(
                f"Ollama did not respond within {self._timeout.read}s. "
                "Try a smaller model or increase --timeout."
            ) from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _stream(self, payload: dict) -> AsyncIterator[str]:
        """Yield response tokens from the streaming Ollama endpoint."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            async with client.stream("POST", self._url, json=payload) as response:
                response.raise_for_status()
                async for raw_line in response.aiter_lines():
                    if not raw_line.strip():
                        continue
                    try:
                        data = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue
                    token: str = data.get("response", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
