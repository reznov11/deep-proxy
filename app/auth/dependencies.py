from fastapi import HTTPException, Request

from app.auth import SESSION_KEY


async def require_dashboard_auth(request: Request) -> None:
    """
    Require a valid dashboard login session (same cookie as /login).
    Used by /api/logs and /api/search — unauthenticated callers get 401 JSON.
    """
    if not request.session.get(SESSION_KEY):
        raise HTTPException(
            status_code=401,
            detail="Требуется вход — откройте /login (нужна сессионная cookie)",
        )
