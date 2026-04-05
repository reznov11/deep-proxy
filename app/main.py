import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.auth import SESSION_KEY
from app.auth.dependencies import require_dashboard_auth
from app.core.config import get_settings
from app.core.database import get_engine, init_db
from app.core.elastic import close_elasticsearch, ensure_index, get_elasticsearch
from app.models.schemas import ProxyLogDocument
from app.services.logging_service import clamp_proxy_log_bodies, enqueue_log
from app.services.logs_query import fetch_logs_page

logger = logging.getLogger(__name__)

tcp_server: asyncio.Server | None = None

_BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    global tcp_server
    settings = get_settings()
    await init_db()
    await ensure_index()

    if not settings.admin_password:
        logger.warning(
            "ADMIN_PASSWORD is empty — dashboard login is disabled until you set credentials in .env"
        )
    if settings.session_secret.startswith("change-me"):
        logger.warning(
            "SESSION_SECRET is still the default — set a long random value in production (.env)"
        )

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


app = FastAPI(title="Deep Proxy — панель", lifespan=lifespan)

_settings = get_settings()
app.add_middleware(
    SessionMiddleware,
    secret_key=_settings.session_secret,
    session_cookie="deep_proxy_session",
    max_age=60 * 60 * 24 * 7,
    same_site="lax",
)

app.mount("/static", StaticFiles(directory=str(_BASE_DIR / "static")), name="static")


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
@app.get("/api/logs/")
async def api_logs_dashboard(
    _auth: Annotated[None, Depends(require_dashboard_auth)],
    page: int = Query(1, ge=1),
    from_date: str | None = None,
    to_date: str | None = None,
    method: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """
    Paginated logs for the dashboard. Tries Elasticsearch first; falls back to PostgreSQL.
    """
    try:
        return await fetch_logs_page(page, from_date, to_date, method, search)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/search")
@app.get("/api/search/")
async def search_logs(
    _auth: Annotated[None, Depends(require_dashboard_auth)],
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


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get(SESSION_KEY):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(), password: str = Form()):
    settings = get_settings()
    if not settings.admin_password:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Вход не настроен (укажите ADMIN_PASSWORD в .env)."},
            status_code=503,
        )
    if username == settings.admin_username and password == settings.admin_password:
        request.session[SESSION_KEY] = True
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": "Неверное имя пользователя или пароль."},
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not request.session.get(SESSION_KEY):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {})


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
