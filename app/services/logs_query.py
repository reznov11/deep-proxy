"""Dashboard log listing from PostgreSQL (canonical store for the UI)."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from app.core.database import get_session_factory
from app.models.db_models import ProxyLog

PAGE_SIZE = 50


def _escape_ilike(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_iso_datetime(raw: str | None) -> datetime | None:
    if not raw or not raw.strip():
        return None
    s = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _proxy_row_to_item(r: ProxyLog) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "method": r.method,
        "url": r.url,
        "request_headers": r.request_headers,
        "request_cookies": r.request_cookies,
        "request_body": r.request_body,
        "response_status": r.response_status,
        "response_headers": r.response_headers,
        "response_body": r.response_body,
        "duration_ms": r.duration_ms,
        "client_ip": r.client_ip,
        "user_agent": r.user_agent,
        "is_https": r.is_https,
        "tunnel_host": r.tunnel_host,
        "tunnel_port": r.tunnel_port,
    }


async def _query_postgresql(
    page: int,
    from_dt: datetime | None,
    to_dt: datetime | None,
    method: str | None,
    search: str | None,
) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        conditions = []
        if from_dt is not None:
            conditions.append(ProxyLog.timestamp >= from_dt)
        if to_dt is not None:
            conditions.append(ProxyLog.timestamp <= to_dt)
        if method and method.strip():
            conditions.append(ProxyLog.method == method.strip().upper())
        if search and search.strip():
            pat = f"%{_escape_ilike(search.strip())}%"
            conditions.append(ProxyLog.url.ilike(pat, escape="\\"))

        base = select(ProxyLog)
        count_q = select(func.count()).select_from(ProxyLog)
        if conditions:
            for c in conditions:
                base = base.where(c)
                count_q = count_q.where(c)

        total_val = int((await session.execute(count_q)).scalar_one())
        pages = max(1, math.ceil(total_val / PAGE_SIZE)) if total_val else 1
        page = min(max(1, page), pages)

        result = await session.execute(
            base.order_by(ProxyLog.timestamp.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
        )
        rows = result.scalars().all()
        items = [_proxy_row_to_item(r) for r in rows]
        return {"items": items, "total": total_val, "page": page, "pages": pages, "source": "postgresql"}


async def fetch_logs_page(
    page: int,
    from_date: str | None,
    to_date: str | None,
    method: str | None,
    search: str | None,
) -> dict[str, Any]:
    from_dt = _parse_iso_datetime(from_date)
    to_dt = _parse_iso_datetime(to_date)
    if from_date and from_dt is None:
        raise ValueError("неверная дата «с»; используйте формат ISO-8601")
    if to_date and to_dt is None:
        raise ValueError("неверная дата «по»; используйте формат ISO-8601")
    if from_dt and to_dt and from_dt > to_dt:
        raise ValueError("дата «с» не может быть позже даты «по»")

    page = max(1, page)
    return await _query_postgresql(page, from_dt, to_dt, method, search)
