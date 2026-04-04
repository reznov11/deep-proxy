"""
mitmproxy addon: POST decrypted flows to Deep Proxy (PostgreSQL + Elasticsearch).

Why this exists
---------------
With HTTPS, clients use CONNECT. If you chain mitmproxy → upstream:http://127.0.0.1:9090,
mitmproxy forwards CONNECT to Deep Proxy on 9090. Deep Proxy then tunnels opaque TLS bytes
to the origin — it never parses the inner HTTP, so no POST body or headers land in the DB.

mitmproxy *does* hold the decrypted request/response in memory. This addon copies that
data to Deep Proxy over HTTP (port 8001), independent of the 9090 tunnel.

Implementation note: ingestion is triggered from the `response` event (per flow). Using
mitmproxy's `done` hook would be wrong — that hook is for addon shutdown, not per-request.

Run (decrypt + log + still forward traffic through Deep Proxy on 9090)
  mitmproxy --mode upstream:http://127.0.0.1:9090 -p 8080 --ssl-insecure ^
    -s scripts/mitm_deep_proxy_addon.py

Run (log only; mitmproxy talks to the internet directly — no upstream)
  mitmdump -p 8080 --ssl-insecure -s scripts/mitm_deep_proxy_addon.py

Environment:
  DEEP_PROXY_INGEST_URL   default http://127.0.0.1:8001/api/ingest/flow
  DEEP_PROXY_INGEST_TOKEN must match INGEST_API_TOKEN in Deep Proxy .env (if set)
  DEEP_PROXY_MAX_BODY     max bytes per request/response body in JSON (default 524288)

Point your client at mitmproxy (e.g. 127.0.0.1:8080). Install mitmproxy's CA on the client.
Deep Proxy (python -m app.main) must be running (dashboard + ingest on 8001, proxy on 9090).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qs, urlparse

from mitmproxy import ctx, http

INGEST_URL = os.environ.get("DEEP_PROXY_INGEST_URL", "http://127.0.0.1:8001/api/ingest/flow")
INGEST_TOKEN = os.environ.get("DEEP_PROXY_INGEST_TOKEN", "")
MAX_BODY = int(os.environ.get("DEEP_PROXY_MAX_BODY", "524288"))


def _headers_as_dict(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if hasattr(headers, "fields"):
        pairs = headers.fields
    elif hasattr(headers, "multi_items"):
        pairs = headers.multi_items()
    else:
        try:
            pairs = headers.items(multi=True)  # type: ignore[call-arg]
        except TypeError:
            pairs = headers.items()
    for name, value in pairs:
        k = name if isinstance(name, str) else name.decode("latin-1", "replace")
        v = value if isinstance(value, str) else value.decode("latin-1", "replace")
        if k in out:
            out[k] = f"{out[k]}, {v}"
        else:
            out[k] = v
    return out


def _body_text(content: bytes | None) -> tuple[str | None, bool]:
    if not content:
        return None, False
    if len(content) > MAX_BODY:
        content = content[:MAX_BODY]
        try:
            return content.decode("utf-8"), True
        except UnicodeDecodeError:
            return content.decode("latin-1"), True
    try:
        return content.decode("utf-8"), False
    except UnicodeDecodeError:
        return content.decode("latin-1"), False


def _cookie_header(headers: dict[str, str]) -> str | None:
    for k, v in headers.items():
        if k.lower() == "cookie":
            return v
    return None


def _query_params_from_url(url: str) -> dict[str, list[str]] | None:
    q = urlparse(url).query
    if not q:
        return None
    return parse_qs(q, keep_blank_values=True)


def response(flow: http.HTTPFlow) -> None:
    """
    Run after each HTTP response is ready (decrypted app-layer data on the client side).

    Do NOT use mitmproxy's `done` hook here — `done` is a *lifecycle* event (addon/shutdown),
    not "flow finished", so ingest would never run per request.
    """
    if not flow.response:
        return
    req = flow.request
    resp = flow.response

    req_t, req_trunc = _body_text(req.content)
    resp_t, resp_trunc = _body_text(resp.content)
    hdr = _headers_as_dict(req.headers)
    rh = _headers_as_dict(resp.headers)

    duration_ms: float | None = None
    try:
        if req.timestamp_start is not None and resp.timestamp_end is not None:
            duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000.0
    except Exception:
        pass

    client_ip: str | None = None
    try:
        peer = flow.client_conn.peername
        if peer and len(peer) >= 1:
            client_ip = str(peer[0])
    except Exception:
        pass

    payload: dict[str, Any] = {
        "method": req.method,
        "url": req.pretty_url,
        "request_query_params": _query_params_from_url(req.pretty_url),
        "request_headers": hdr,
        "request_cookies": _parse_cookies(_cookie_header(hdr)),
        "request_body": req_t,
        "request_body_truncated": req_trunc,
        "response_status": resp.status_code,
        "response_headers": rh,
        "response_body": resp_t,
        "response_body_truncated": resp_trunc,
        "duration_ms": duration_ms,
        "client_ip": client_ip,
        "user_agent": hdr.get("User-Agent") or hdr.get("user-agent"),
        "is_https": req.scheme == "https",
        "proxy_note": "mitmproxy → Deep Proxy ingest",
    }

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        INGEST_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    if INGEST_TOKEN:
        request.add_header("X-Deep-Proxy-Ingest-Token", INGEST_TOKEN)
    try:
        urllib.request.urlopen(request, timeout=15)
        ctx.log.info(f"Deep Proxy ingest OK {req.method} {req.pretty_url}")
    except urllib.error.HTTPError as e:
        body = e.read()[:2000]
        ctx.log.error(f"Deep Proxy ingest HTTP {e.code}: {body!r}")
    except Exception as e:
        ctx.log.error(f"Deep Proxy ingest failed: {e}")


def _parse_cookies(cookie_header: str | None) -> dict[str, str] | None:
    if not cookie_header:
        return None
    out: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out or None
