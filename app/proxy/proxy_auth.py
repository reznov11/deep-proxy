"""HTTP forward proxy: Basic Proxy-Authorization validation."""

import base64
import binascii
import secrets
from typing import Mapping

from app.core.config import Settings


def proxy_auth_is_required(settings: Settings) -> bool:
    u = (settings.proxy_user or "").strip()
    p = (settings.proxy_pass or "").strip()
    if not u or not p:
        return False
    return bool(settings.proxy_require_auth)


def _header_ci(headers: Mapping[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def verify_proxy_basic_auth(headers: Mapping[str, str], settings: Settings) -> bool:
    if not proxy_auth_is_required(settings):
        return True
    raw = _header_ci(headers, "proxy-authorization")
    if not raw:
        return False
    prefix = "basic "
    if not raw.lower().startswith(prefix):
        return False
    b64 = raw[len(prefix) :].strip()
    try:
        decoded = base64.b64decode(b64, validate=False).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    if ":" not in decoded:
        return False
    user, _, password = decoded.partition(":")
    eu = (settings.proxy_user or "").strip()
    ep = (settings.proxy_pass or "").strip()
    return secrets.compare_digest(user, eu) and secrets.compare_digest(password, ep)
