"""Dashboard log listing: Elasticsearch primary, PostgreSQL fallback."""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.database import get_session_factory
from app.core.elastic import get_elasticsearch
from app.models.db_models import ProxyLog

logger = logging.getLogger(__name__)

PAGE_SIZE = 50


def _escape_ilike(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _escape_es_wildcard(s: str) -> str:
    return s.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


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


def _es_hit_to_item(hit: dict[str, Any]) -> dict[str, Any]:
    src = dict(hit.get("_source") or {})
    if "id" not in src and hit.get("_id"):
        src["id"] = hit["_id"]
    ts = src.get("timestamp")
    if isinstance(ts, datetime):
        src["timestamp"] = ts.isoformat()
    return src


def _build_es_bool_filter(
    from_dt: datetime | None,
    to_dt: datetime | None,
    method: str | None,
    search: str | None,
) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    if from_dt is not None or to_dt is not None:
        rng: dict[str, Any] = {}
        if from_dt is not None:
            rng["gte"] = from_dt.isoformat()
        if to_dt is not None:
            rng["lte"] = to_dt.isoformat()
        must.append({"range": {"timestamp": rng}})
    if method and method.strip():
        must.append({"term": {"method": method.strip().upper()}})
    if search and search.strip():
        q = search.strip()
        esc = _escape_es_wildcard(q)
        must.append(
            {
                "bool": {
                    "should": [
                        {"match": {"url": {"query": q, "operator": "and"}}},
                        {"wildcard": {"url": f"*{esc}*"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    if not must:
        return {"match_all": {}}
    return {"bool": {"must": must}}


async def _query_elasticsearch(
    page: int,
    from_dt: datetime | None,
    to_dt: datetime | None,
    method: str | None,
    search: str | None,
) -> dict[str, Any] | None:
    settings = get_settings()
    client = get_elasticsearch()
    index = settings.elasticsearch_index
    query = _build_es_bool_filter(from_dt, to_dt, method, search)
    body: dict[str, Any] = {
        "track_total_hits": True,
        "from": (page - 1) * PAGE_SIZE,
        "size": PAGE_SIZE,
        "query": query,
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    try:
        resp = await client.search(index=index, body=body)
    except Exception as e:
        logger.warning("Elasticsearch search failed, falling back to PostgreSQL: %s", e)
        return None

    hits = resp.get("hits", {})
    raw_hits = hits.get("hits", [])
    items = [_es_hit_to_item(h) for h in raw_hits]
    total = hits.get("total", {})
    if isinstance(total, dict):
        total_val = int(total.get("value", 0))
    else:
        total_val = int(total or 0)
    pages = max(1, math.ceil(total_val / PAGE_SIZE)) if total_val else 1
    return {"items": items, "total": total_val, "page": page, "pages": pages, "source": "elasticsearch"}


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

    es_result = await _query_elasticsearch(page, from_dt, to_dt, method, search)
    if es_result is not None:
        return es_result
    return await _query_postgresql(page, from_dt, to_dt, method, search)
