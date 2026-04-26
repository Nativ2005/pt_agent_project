from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, field_validator


class BurpRequest(BaseModel):
    """A single HTTP request extracted from a Burp Suite XML export."""

    host: str
    path: str
    method: str
    headers: dict[str, str] = {}
    body: str = ""

    @field_validator("method")
    @classmethod
    def normalise_method(cls, v: str) -> str:
        return v.upper()

    @field_validator("path")
    @classmethod
    def ensure_leading_slash(cls, v: str) -> str:
        return v if v.startswith("/") else f"/{v}"


class SwaggerEndpoint(BaseModel):
    """A single path+method combination extracted from a Swagger / OpenAPI spec."""

    base_url: str
    path: str
    method: str
    operation_id: Optional[str] = None
    parameters: list[str] = []
    summary: Optional[str] = None

    @field_validator("method")
    @classmethod
    def normalise_method(cls, v: str) -> str:
        return v.upper()

    @property
    def full_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.path.lstrip('/')}"
