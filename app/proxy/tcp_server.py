import asyncio
import logging

from app.core.config import get_settings
from app.models.schemas import ProxyLogDocument
from app.proxy.http_common import (
    HEADER_MAX,
    IncomingBodyTooLarge,
    h11_headers_to_list,
    parse_header_block,
    read_http_message,
)
from app.proxy.http_handler import forward_http_proxy_stream
from app.proxy.https_tunnel import parse_connect_target, run_connect_tunnel
from app.proxy.proxy_auth import verify_proxy_basic_auth
from app.services.logging_service import enqueue_log, extract_query_params, parse_cookie_header

logger = logging.getLogger(__name__)

_PROXY_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="DeepProxy"\r\n'
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


async def read_until_double_crlf(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(4096)
        if not chunk:
            raise EOFError()
        buf += chunk
        if len(buf) > HEADER_MAX:
            raise ValueError("headers too large")
    idx = buf.index(b"\r\n\r\n")
    head = buf[:idx]
    rest = buf[idx + 4 :]
    return head, rest


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else None
    try:
        head, rest = await read_until_double_crlf(reader)
    except (EOFError, ValueError) as e:
        logger.debug("Client closed or bad headers: %s", e)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    first_line = head.split(b"\r\n", 1)[0]
    parts = first_line.split(None, 2)
    if len(parts) < 3:
        try:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    method = parts[0].upper()
    target = parts[1]
    settings = get_settings()

    if method == b"CONNECT":
        host, port = parse_connect_target(target)
        connect_headers = parse_header_block(head)
        if not verify_proxy_basic_auth(connect_headers, settings):
            cookie_header = next(
                (v for k, v in connect_headers.items() if k.lower() == "cookie"),
                None,
            )
            ua = next(
                (v for k, v in connect_headers.items() if k.lower() == "user-agent"),
                None,
            )
            await enqueue_log(
                ProxyLogDocument(
                    method="CONNECT",
                    url=f"https://{host}:{port}/",
                    is_https=True,
                    tunnel_host=host,
                    tunnel_port=port,
                    request_query_params=extract_query_params(f"https://{host}:{port}/"),
                    request_headers=connect_headers or None,
                    request_cookies=parse_cookie_header(cookie_header) or None,
                    client_ip=client_ip,
                    user_agent=ua,
                    response_status=407,
                    proxy_note="HTTPS tunnel: proxy authentication required (TLS opaque; no decrypted content)",
                )
            )
            try:
                writer.write(_PROXY_407)
                await writer.drain()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return
        await run_connect_tunnel(
            reader, writer, host, port, rest, client_ip, connect_headers=connect_headers
        )
        return

    req_headers_early = parse_header_block(head)
    if not verify_proxy_basic_auth(req_headers_early, settings):
        method_s = parts[0].decode("latin1", errors="replace")
        url = parts[1].decode("latin1", errors="replace") if len(parts) > 1 else ""
        cookie_header = next(
            (v for k, v in req_headers_early.items() if k.lower() == "cookie"),
            None,
        )
        ua = next(
            (v for k, v in req_headers_early.items() if k.lower() == "user-agent"),
            None,
        )
        is_https = url.strip().lower().startswith("https:")
        await enqueue_log(
            ProxyLogDocument(
                method=method_s,
                url=url,
                is_https=is_https,
                request_query_params=extract_query_params(url) if url else None,
                request_headers=req_headers_early or None,
                request_cookies=parse_cookie_header(cookie_header) or None,
                client_ip=client_ip,
                user_agent=ua,
                response_status=407,
                proxy_note="proxy authentication required",
            )
        )
        try:
            writer.write(_PROXY_407)
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    try:
        full_initial = head + b"\r\n\r\n" + rest
        req, body = await read_http_message(
            reader,
            full_initial,
            max_body_bytes=settings.max_incoming_request_body_bytes,
        )
    except IncomingBodyTooLarge as e:
        logger.warning("Request body too large: %s", e)
        method_s = parts[0].decode("latin1", errors="replace")
        url = parts[1].decode("latin1", errors="replace") if len(parts) > 1 else ""
        rh = parse_header_block(head)
        ck = next((v for k, v in rh.items() if k.lower() == "cookie"), None)
        ua = next((v for k, v in rh.items() if k.lower() == "user-agent"), None)
        await enqueue_log(
            ProxyLogDocument(
                method=method_s,
                url=url,
                is_https=url.strip().lower().startswith("https:"),
                request_query_params=extract_query_params(url) if url else None,
                request_headers=rh or None,
                request_cookies=parse_cookie_header(ck) or None,
                client_ip=client_ip,
                user_agent=ua,
                response_status=413,
                proxy_note=str(e),
            )
        )
        msg = b"Payload Too Large"
        try:
            writer.write(
                (
                    b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\n"
                    b"Connection: close\r\nContent-Length: %d\r\n\r\n" % len(msg)
                )
                + msg
            )
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return
    except Exception as e:
        logger.exception("Parse HTTP error: %s", e)
        method_s = parts[0].decode("latin1", errors="replace")
        url = parts[1].decode("latin1", errors="replace") if len(parts) > 1 else ""
        rh = parse_header_block(head)
        ck = next((v for k, v in rh.items() if k.lower() == "cookie"), None)
        ua = next((v for k, v in rh.items() if k.lower() == "user-agent"), None)
        await enqueue_log(
            ProxyLogDocument(
                method=method_s,
                url=url,
                is_https=url.strip().lower().startswith("https:"),
                request_query_params=extract_query_params(url) if url else None,
                request_headers=rh or None,
                request_cookies=parse_cookie_header(ck) or None,
                client_ip=client_ip,
                user_agent=ua,
                response_status=400,
                proxy_note=f"invalid HTTP request: {e}",
            )
        )
        try:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    method_s = req.method.decode("latin1")
    url = req.target.decode("latin1")
    header_list = h11_headers_to_list(req.headers)

    async def write(b: bytes) -> None:
        writer.write(b)

    async def drain() -> None:
        await writer.drain()

    try:
        await forward_http_proxy_stream(method_s, url, header_list, body, client_ip, write, drain)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve_tcp_proxy(host: str, port: int) -> asyncio.Server:
    return await asyncio.start_server(handle_client, host, port)
