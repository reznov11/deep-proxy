from typing import Any

import h11

HEADER_MAX = 1 << 20


def parse_header_block(head: bytes) -> dict[str, str]:
    """Parse header lines from raw HTTP message head (request line + headers, no body)."""
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


class IncomingBodyTooLarge(ValueError):
    """Raised when request body exceeds configured max while reading from client."""


async def read_http_message(
    reader: Any,
    initial: bytes,
    *,
    max_body_bytes: int | None = None,
) -> tuple[h11.Request, bytes]:
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(initial)
    req: h11.Request | None = None
    body_parts: list[bytes] = []
    body_total = 0
    while True:
        try:
            event = conn.next_event()
        except h11.ProtocolError as e:
            raise ValueError(f"invalid HTTP message: {e}") from e
        if event is h11.NEED_DATA:
            chunk = await reader.read(65536)
            if not chunk:
                raise EOFError()
            conn.receive_data(chunk)
            continue
        if isinstance(event, h11.Request):
            req = event
        elif isinstance(event, h11.Data):
            body_total += len(event.data)
            if max_body_bytes is not None and body_total > max_body_bytes:
                raise IncomingBodyTooLarge(
                    f"request body larger than {max_body_bytes} bytes"
                )
            body_parts.append(event.data)
        elif isinstance(event, h11.EndOfMessage):
            break
        elif isinstance(event, h11.ConnectionClosed):
            raise EOFError()
        else:
            raise RuntimeError(f"unexpected h11 event: {event!r}")
    if req is None:
        raise ValueError("no request line")
    return req, b"".join(body_parts)


def h11_headers_to_list(headers: Any) -> list[tuple[str, str]]:
    """h11.Headers is a Sequence[(bytes, bytes)], not a dict — no .items()."""
    out: list[tuple[str, str]] = []
    pairs = headers.raw_items() if hasattr(headers, "raw_items") else headers
    for name, value in pairs:
        n = name.decode("latin1") if isinstance(name, (bytes, bytearray)) else str(name)
        v = value.decode("latin1") if isinstance(value, (bytes, bytearray)) else str(value)
        out.append((n, v))
    return out
