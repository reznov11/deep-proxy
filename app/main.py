import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.database import get_engine, get_session_factory, init_db
from app.core.elastic import close_elasticsearch, ensure_index, get_elasticsearch
from app.models.db_models import ProxyLog
from app.models.schemas import ProxyLogDocument
from app.services.logging_service import clamp_proxy_log_bodies, enqueue_log

logger = logging.getLogger(__name__)

tcp_server: asyncio.Server | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global tcp_server
    settings = get_settings()
    await init_db()
    await ensure_index()

    if not settings.ingest_api_token:
        logger.warning(
            "Ingest API /api/ingest/flow has no INGEST_API_TOKEN — anyone who can reach the dashboard can post logs."
        )

    from app.services.logging_service import start_logging_worker, stop_logging_worker
    from app.proxy.tcp_server import serve_tcp_proxy

    await start_logging_worker()
    tcp_server = await serve_tcp_proxy("0.0.0.0", settings.proxy_port)
    logger.info("Forward proxy listening on 0.0.0.0:%s", settings.proxy_port)

    try:
        yield
    finally:
        if tcp_server is not None:
            tcp_server.close()
            await tcp_server.wait_closed()
        await stop_logging_worker()
        await close_elasticsearch()
        await get_engine().dispose()


app = FastAPI(title="Deep Proxy Dashboard", lifespan=lifespan)


@app.post("/api/ingest/flow")
async def ingest_flow_from_mitmproxy(
    body: ProxyLogDocument,
    x_deep_proxy_ingest_token: str | None = Header(default=None, alias="X-Deep-Proxy-Ingest-Token"),
) -> dict[str, str]:
    """
    Push one decrypted HTTP(S) flow (e.g. from mitmproxy addon) into the same PG + ES pipeline as the TCP proxy.
    Set INGEST_API_TOKEN in .env and send it as header X-Deep-Proxy-Ingest-Token.
    """
    settings = get_settings()
    if settings.ingest_api_token:
        if x_deep_proxy_ingest_token != settings.ingest_api_token:
            raise HTTPException(status_code=403, detail="invalid or missing ingest token")
    doc = clamp_proxy_log_bodies(body, settings.max_body_storage_bytes)
    if not doc.proxy_note:
        doc = doc.model_copy(update={"proxy_note": "ingested via /api/ingest/flow (e.g. mitmproxy)"})
    await enqueue_log(doc)
    return {"status": "queued"}


@app.get("/api/logs")
async def list_logs(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        total = (await session.execute(select(func.count()).select_from(ProxyLog))).scalar_one()
        result = await session.execute(
            select(ProxyLog).order_by(ProxyLog.timestamp.desc()).offset(offset).limit(limit)
        )
        rows = result.scalars().all()
        items: list[dict[str, Any]] = []
        for r in rows:
            items.append(
                {
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
            )
        return {"items": items, "total": total, "offset": offset, "limit": limit}


@app.get("/api/search")
async def search_logs(
    q: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
) -> dict[str, Any]:
    settings = get_settings()
    es = get_elasticsearch()
    index = settings.elasticsearch_index
    if q:
        body: dict[str, Any] = {
            "query": {"query_string": {"query": q}},
            "from": offset,
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
    else:
        body = {
            "query": {"match_all": {}},
            "from": offset,
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
    resp = await es.search(index=index, body=body)
    hits = resp.get("hits", {})
    items = []
    for h in hits.get("hits", []):
        src = dict(h.get("_source") or {})
        src["_id"] = h.get("_id")
        items.append(src)
    total = hits.get("total", {})
    if isinstance(total, dict):
        total_val = total.get("value", 0)
    else:
        total_val = total
    return {"items": items, "total": total_val, "offset": offset, "limit": limit}


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.dashboard_port,
        log_level="info",
    )
