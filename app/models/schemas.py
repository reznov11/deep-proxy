from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ProxyLogDocument(BaseModel):
    """Structured log for PostgreSQL + Elasticsearch."""

    id: UUID | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    method: str | None = None
    url: str | None = None
    request_query_params: dict[str, list[str]] | None = None
    request_headers: dict[str, Any] | None = None
    request_cookies: dict[str, str] | None = None
    request_body: str | None = None
    request_body_truncated: bool = False
    parsed_request_body: dict[str, Any] | list[Any] | str | None = None
    response_status: int | None = None
    response_headers: dict[str, Any] | None = None
    response_cookies: dict[str, str] | None = None
    response_body: str | None = None
    response_body_truncated: bool = False
    parsed_response_body: dict[str, Any] | list[Any] | str | None = None
    duration_ms: float | None = None
    client_ip: str | None = None
    user_agent: str | None = None
    is_https: bool = False
    tunnel_host: str | None = None
    tunnel_port: int | None = None
    tunnel_bytes_sent: int | None = None
    tunnel_bytes_received: int | None = None
    proxy_note: str | None = None


class LogListResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    offset: int
    limit: int
