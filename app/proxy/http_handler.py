import logging
import time
from typing import Awaitable, Callable
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.models.schemas import ProxyLogDocument
from app.services.logging_service import (
    enqueue_log,
    extract_query_params,
    parse_cookie_header,
    parse_set_cookie_from_httpx,
    truncate_body,
)

logger = logging.getLogger(__name__)

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    }
)


def _normalized_header_list(headers: list[tuple[str, str]]) -> dict[str, str]:
    """Lowercase keys; duplicate names merged with comma (RFC 7230 style)."""
    out: dict[str, str] = {}
    for name, value in headers:
        lk = name.lower()
        if lk in out:
            out[lk] = f"{out[lk]}, {value}"
        else:
            out[lk] = value
    return out


def _filter_request_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers:
        if name.lower() in HOP_BY_HOP:
            continue
        out[name] = value
    return out


def _filter_response_headers(hdrs: httpx.Headers) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in hdrs.multi_items():
        if key.lower() in HOP_BY_HOP:
            continue
        out.append((key, value))
    return out


def _normalized_headers_from_httpx(hdrs: httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in hdrs.multi_items():
        lk = k.lower()
        if lk in out:
            out[lk] = f"{out[lk]}, {v}"
        else:
            out[lk] = v
    return out


def _ensure_absolute_http_url(url: str) -> tuple[str | None, str | None]:
    u = url.strip()
    if not u:
        return None, "empty URL"
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https"):
        return None, "unsupported scheme"
    if not parsed.netloc:
        return None, "missing host"
    return u, None


def _url_is_https(url: str) -> bool:
    return urlparse(url.strip()).scheme.lower() == "https"


async def forward_http_proxy_stream(
    method: str,
    url: str,
    header_list: list[tuple[str, str]],
    body: bytes,
    client_ip: str | None,
    write: Callable[[bytes], Awaitable[None]],
    drain: Callable[[], Awaitable[None]],
) -> None:
    settings = get_settings()
    valid_url, err = _ensure_absolute_http_url(url)
    cookie_header = next((v for k, v in header_list if k.lower() == "cookie"), None)
    ua = next((v for k, v in header_list if k.lower() == "user-agent"), None)
    req_headers_log = _normalized_header_list(header_list)
    req_body_text, req_trunc = truncate_body(body, settings.max_body_storage_bytes)

    if not valid_url:
        msg = f"Bad Request: {err or 'invalid URL'}"
        payload = (
            f"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(msg)}\r\nConnection: close\r\n\r\n{msg}"
        )
        await write(payload.encode("utf-8"))
        await drain()
        await enqueue_log(
            ProxyLogDocument(
                method=method,
                url=url,
                is_https=_url_is_https(url),
                request_query_params=extract_query_params(url) if url else None,
                request_headers=req_headers_log,
                request_cookies=parse_cookie_header(cookie_header),
                request_body=req_body_text,
                request_body_truncated=req_trunc,
                response_status=400,
                client_ip=client_ip,
                user_agent=ua,
            )
        )
        return

    t0 = time.perf_counter()
    is_https = _url_is_https(valid_url)
    req_headers = _filter_request_headers(header_list)
    if "host" not in {k.lower() for k in req_headers}:
        host = urlparse(valid_url).netloc
        if host:
            req_headers["Host"] = host

    timeout = httpx.Timeout(120.0, connect=30.0)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)

    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False, trust_env=False) as client:
        try:
            req = client.build_request(
                method,
                valid_url,
                headers=req_headers,
                content=body if body else None,
            )
            async with client.send(req, stream=True) as resp:
                reason = resp.reason_phrase or ""
                resp_headers = _filter_response_headers(resp.headers)
                header_bytes = bytearray()
                header_bytes.extend(f"HTTP/1.1 {resp.status_code} {reason}\r\n".encode("latin1"))
                for k, v in resp_headers:
                    header_bytes.extend(f"{k}: {v}\r\n".encode("latin1"))
                header_bytes.extend(b"Connection: close\r\n\r\n")
                await write(bytes(header_bytes))
                await drain()

                collected = bytearray()
                max_b = settings.max_body_storage_bytes
                truncated = False
                async for chunk in resp.aiter_raw():
                    if chunk:
                        await write(chunk)
                        await drain()
                        if len(collected) < max_b:
                            room = max_b - len(collected)
                            take = chunk[:room]
                            collected.extend(take)
                            if len(chunk) > room:
                                truncated = True

                status = resp.status_code
                resp_hdr_log = _normalized_headers_from_httpx(resp.headers)
                resp_body_text, resp_trunc = truncate_body(bytes(collected), max_b)
                if truncated:
                    resp_trunc = True
                resp_cookies = parse_set_cookie_from_httpx(resp)
                duration_ms = (time.perf_counter() - t0) * 1000

        except httpx.TimeoutException:
            err_body = b"Gateway Timeout"
            await write(
                b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 15\r\nConnection: close\r\n\r\n" + err_body
            )
            await drain()
            duration_ms = (time.perf_counter() - t0) * 1000
            await enqueue_log(
                ProxyLogDocument(
                    method=method,
                    url=valid_url,
                    is_https=is_https,
                    request_query_params=extract_query_params(valid_url),
                    request_headers=req_headers_log,
                    request_cookies=parse_cookie_header(cookie_header),
                    request_body=req_body_text,
                    request_body_truncated=req_trunc,
                    response_status=504,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    user_agent=ua,
                )
            )
            return
        except Exception as e:
            logger.exception("Upstream error: %s", e)
            err_body = b"Bad Gateway"
            await write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nConnection: close\r\n\r\n" + err_body
            )
            await drain()
            duration_ms = (time.perf_counter() - t0) * 1000
            await enqueue_log(
                ProxyLogDocument(
                    method=method,
                    url=valid_url,
                    is_https=is_https,
                    request_query_params=extract_query_params(valid_url),
                    request_headers=req_headers_log,
                    request_cookies=parse_cookie_header(cookie_header),
                    request_body=req_body_text,
                    request_body_truncated=req_trunc,
                    response_status=502,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    user_agent=ua,
                )
            )
            return

        await enqueue_log(
            ProxyLogDocument(
                method=method,
                url=valid_url,
                is_https=is_https,
                request_query_params=extract_query_params(valid_url),
                request_headers=req_headers_log,
                request_cookies=parse_cookie_header(cookie_header),
                request_body=req_body_text,
                request_body_truncated=req_trunc,
                response_status=status,
                response_headers=resp_hdr_log,
                response_cookies=resp_cookies,
                response_body=resp_body_text,
                response_body_truncated=resp_trunc,
                duration_ms=duration_ms,
                client_ip=client_ip,
                user_agent=ua,
            )
        )
