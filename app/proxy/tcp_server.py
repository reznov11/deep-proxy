import asyncio
import logging

from app.core.config import get_settings
from app.proxy.http_common import (
    HEADER_MAX,
    IncomingBodyTooLarge,
    h11_headers_to_list,
    read_http_message,
)
from app.proxy.http_handler import forward_http_proxy_stream
from app.proxy.https_tunnel import parse_connect_target, run_connect_tunnel

logger = logging.getLogger(__name__)


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


def parse_connect_header_block(head: bytes) -> dict[str, str]:
    """Parse raw header lines after the request line (CONNECT ... HTTP/1.x)."""
    lines = head.split(b"\r\n")
    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if not raw.strip():
            continue
        if b":" not in raw:
            continue
        name, value = raw.split(b":", 1)
        headers[name.decode("latin1").strip()] = value.decode("latin1").strip()
    return headers


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

    if method == b"CONNECT":
        connect_headers = parse_connect_header_block(head)
        host, port = parse_connect_target(target)
        await run_connect_tunnel(
            reader, writer, host, port, rest, client_ip, connect_headers=connect_headers
        )
        return

    settings = get_settings()
    try:
        full_initial = head + b"\r\n\r\n" + rest
        req, body = await read_http_message(
            reader,
            full_initial,
            max_body_bytes=settings.max_incoming_request_body_bytes,
        )
    except IncomingBodyTooLarge as e:
        logger.warning("Request body too large: %s", e)
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
