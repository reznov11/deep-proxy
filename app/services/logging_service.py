import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import httpx

from app.core.config import get_settings
from app.core.database import get_session_factory
from app.core.elastic import get_elasticsearch
from app.models.db_models import ProxyLog
from app.models.schemas import ProxyLogDocument

logger = logging.getLogger(__name__)

_log_queue: asyncio.Queue[ProxyLogDocument | None] | None = None
_worker_task: asyncio.Task | None = None


def get_log_queue() -> asyncio.Queue[ProxyLogDocument | None]:
    global _log_queue
    if _log_queue is None:
        _log_queue = asyncio.Queue(maxsize=10_000)
    return _log_queue


def _try_parse_json(s: str) -> dict[str, Any] | list[Any] | None:
    s = s.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def _try_parse_form(s: str) -> dict[str, list[str]] | None:
    if "=" not in s:
        return None
    try:
        return parse_qs(s, keep_blank_values=True)
    except Exception:
        return None


def enrich_parsed_bodies(doc: ProxyLogDocument) -> None:
    if doc.request_body:
        j = _try_parse_json(doc.request_body)
        if j is not None:
            doc.parsed_request_body = j
        else:
            f = _try_parse_form(doc.request_body)
            if f is not None:
                doc.parsed_request_body = {k: v[0] if len(v) == 1 else v for k, v in f.items()}
    if doc.response_body:
        j = _try_parse_json(doc.response_body)
        if j is not None:
            doc.parsed_response_body = j


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    out: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_set_cookie_from_httpx(resp: httpx.Response) -> dict[str, str]:
    """Extract cookie names from Set-Cookie response headers (first name=value segment)."""
    out: dict[str, str] = {}
    for k, v in resp.headers.multi_items():
        if k.lower() != "set-cookie":
            continue
        sem = v.split(";", 1)[0]
        if "=" in sem:
            name, val = sem.split("=", 1)
            out[name.strip()] = val.strip()
    return out


def clamp_proxy_log_bodies(doc: ProxyLogDocument, max_bytes: int) -> ProxyLogDocument:
    """Truncate request/response body text to max_bytes (for ingest and safety)."""
    out = doc.model_copy(deep=True)
    if out.request_body:
        t, tr = truncate_body(out.request_body.encode("utf-8", errors="replace"), max_bytes)
        out.request_body = t
        out.request_body_truncated = out.request_body_truncated or tr
    if out.response_body:
        t, tr = truncate_body(out.response_body.encode("utf-8", errors="replace"), max_bytes)
        out.response_body = t
        out.response_body_truncated = out.response_body_truncated or tr
    return out


def truncate_body(raw: bytes | None, max_bytes: int) -> tuple[str | None, bool]:
    if raw is None:
        return None, False
    if len(raw) <= max_bytes:
        try:
            return raw.decode("utf-8"), False
        except UnicodeDecodeError:
            return raw.decode("latin-1"), False
    truncated = raw[:max_bytes]
    try:
        text = truncated.decode("utf-8")
    except UnicodeDecodeError:
        text = truncated.decode("latin-1")
    return text, True


async def enqueue_log(doc: ProxyLogDocument) -> None:
    enrich_parsed_bodies(doc)
    q = get_log_queue()
    try:
        q.put_nowait(doc)
    except asyncio.QueueFull:
        logger.warning("Log queue full; dropping log entry")


async def _persist(doc: ProxyLogDocument) -> None:
    settings = get_settings()
    es = get_elasticsearch()
    index = settings.elasticsearch_index

    if doc.id is None:
        doc.id = uuid.uuid4()

    doc_dict = doc.model_dump(mode="json", exclude_none=True)
    doc_dict["id"] = str(doc.id)
    doc_dict["timestamp"] = doc.timestamp.isoformat()

    await es.index(index=index, document=doc_dict, id=str(doc.id))

    factory = get_session_factory()
    req_headers_pg: dict | None = None
    if doc.request_headers or doc.request_query_params:
        req_headers_pg = dict(doc.request_headers) if doc.request_headers else {}
        if doc.request_query_params:
            req_headers_pg = {**req_headers_pg, "query_params": doc.request_query_params}
    if doc.proxy_note:
        if req_headers_pg is None:
            req_headers_pg = {}
        else:
            req_headers_pg = dict(req_headers_pg)
        req_headers_pg["_proxy_note"] = doc.proxy_note

    async with factory() as session:
        row = ProxyLog(
            id=doc.id or uuid.uuid4(),
            timestamp=doc.timestamp.replace(tzinfo=timezone.utc)
            if doc.timestamp.tzinfo is None
            else doc.timestamp,
            method=doc.method,
            url=doc.url,
            request_headers=req_headers_pg,
            request_cookies=doc.request_cookies,
            request_body=doc.request_body,
            response_status=doc.response_status,
            response_headers=doc.response_headers,
            response_body=doc.response_body,
            duration_ms=doc.duration_ms,
            client_ip=doc.client_ip,
            user_agent=doc.user_agent,
            is_https=doc.is_https,
            tunnel_host=doc.tunnel_host,
            tunnel_port=doc.tunnel_port,
        )
        session.add(row)
        await session.commit()


async def _worker() -> None:
    q = get_log_queue()
    while True:
        doc = await q.get()
        try:
            if doc is None:
                break
            await _persist(doc)
        except Exception:
            logger.exception("Failed to persist log")
        finally:
            q.task_done()


async def start_logging_worker() -> None:
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker())


async def stop_logging_worker() -> None:
    global _worker_task
    q = get_log_queue()
    await q.put(None)
    if _worker_task:
        await _worker_task
        _worker_task = None


def headers_to_dict(header_list: list[tuple[str, str]]) -> dict[str, str]:
    d: dict[str, str] = {}
    for k, v in header_list:
        lk = k.lower()
        if lk in d:
            d[k] = f"{d[k]}, {v}"
        else:
            d[k] = v
    return d


def extract_query_params(url: str) -> dict[str, list[str]]:
    from urllib.parse import urlparse, parse_qs

    q = urlparse(url).query
    if not q:
        return {}
    return parse_qs(q, keep_blank_values=True)
