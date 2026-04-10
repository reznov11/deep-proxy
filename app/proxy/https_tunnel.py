"""
CONNECT support: opaque TCP tunnel only (no TLS termination).

HTTPS request/response bodies inside the tunnel are encrypted end-to-end; this proxy only
logs CONNECT metadata and byte counts, not decrypted application data.
"""
import asyncio
import logging
import time

from app.models.schemas import ProxyLogDocument
from app.services.logging_service import enqueue_log, parse_cookie_header

logger = logging.getLogger(__name__)


def _header_ci(headers: dict[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _connect_cookies(connect_headers: dict[str, str] | None) -> dict[str, str] | None:
    raw = _header_ci(connect_headers or {}, "cookie")
    cookies = parse_cookie_header(raw)
    return cookies if cookies else None


def _parse_host_port(target: bytes) -> tuple[str, int]:
    t = target.decode("latin1")
    if ":" in t:
        host, port_s = t.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return t, 443
    return t, 443


async def run_connect_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    host: str,
    port: int,
    initial_from_client: bytes,
    client_ip: str | None,
    connect_headers: dict[str, str] | None = None,
) -> None:
    """Blind TCP tunnel after CONNECT 200. TLS is not terminated; logs are metadata-only."""
    t0 = time.perf_counter()
    bytes_up = 0
    bytes_down = 0

    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=30.0,
        )
    except TimeoutError:
        msg = b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            client_writer.write(msg)
            await client_writer.drain()
        except Exception:
            pass
        await enqueue_log(
            ProxyLogDocument(
                method="CONNECT",
                url=f"https://{host}:{port}/",
                is_https=True,
                tunnel_host=host,
                tunnel_port=port,
                client_ip=client_ip,
                request_headers=connect_headers or None,
                request_cookies=_connect_cookies(connect_headers),
                user_agent=_header_ci(connect_headers or {}, "user-agent"),
                response_status=504,
                duration_ms=(time.perf_counter() - t0) * 1000,
                proxy_note="HTTPS tunnel: upstream connect failed (TLS opaque)",
            )
        )
        return
    except OSError as e:
        logger.warning("CONNECT upstream failed %s:%s: %s", host, port, e)
        msg = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            client_writer.write(msg)
            await client_writer.drain()
        except Exception:
            pass
        await enqueue_log(
            ProxyLogDocument(
                method="CONNECT",
                url=f"https://{host}:{port}/",
                is_https=True,
                tunnel_host=host,
                tunnel_port=port,
                client_ip=client_ip,
                request_headers=connect_headers or None,
                request_cookies=_connect_cookies(connect_headers),
                user_agent=_header_ci(connect_headers or {}, "user-agent"),
                response_status=502,
                duration_ms=(time.perf_counter() - t0) * 1000,
                proxy_note="HTTPS tunnel: upstream connect failed (TLS opaque)",
            )
        )
        return

    try:
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()
    except Exception:
        try:
            upstream_writer.close()
            await upstream_writer.wait_closed()
        except Exception:
            pass
        return

    if initial_from_client:
        try:
            upstream_writer.write(initial_from_client)
            await upstream_writer.drain()
            bytes_up += len(initial_from_client)
        except Exception:
            try:
                upstream_writer.close()
                client_writer.close()
            except Exception:
                pass
            return

    async def pump_client_to_upstream() -> None:
        nonlocal bytes_up
        try:
            while True:
                data = await client_reader.read(65536)
                if not data:
                    break
                bytes_up += len(data)
                upstream_writer.write(data)
                await upstream_writer.drain()
        except Exception:
            pass
        finally:
            try:
                upstream_writer.close()
            except Exception:
                pass

    async def pump_upstream_to_client() -> None:
        nonlocal bytes_down
        try:
            while True:
                data = await upstream_reader.read(65536)
                if not data:
                    break
                bytes_down += len(data)
                client_writer.write(data)
                await client_writer.drain()
        except Exception:
            pass
        finally:
            try:
                client_writer.close()
            except Exception:
                pass

    await asyncio.gather(pump_client_to_upstream(), pump_upstream_to_client())
    duration_ms = (time.perf_counter() - t0) * 1000

    await enqueue_log(
        ProxyLogDocument(
            method="CONNECT",
            url=f"https://{host}:{port}/",
            is_https=True,
            tunnel_host=host,
            tunnel_port=port,
            client_ip=client_ip,
            request_headers=connect_headers or None,
            request_cookies=_connect_cookies(connect_headers),
            user_agent=_header_ci(connect_headers or {}, "user-agent"),
            response_status=200,
            duration_ms=duration_ms,
            tunnel_bytes_sent=bytes_up,
            tunnel_bytes_received=bytes_down,
            proxy_note="HTTPS CONNECT tunnel closed (TLS opaque; metadata and byte counts only)",
        )
    )


def parse_connect_target(target: bytes) -> tuple[str, int]:
    return _parse_host_port(target)
