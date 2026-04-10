from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# app/core/config.py -> parents: core, app, project root
_APP_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _APP_DIR.parent

# Load both project-root and app/.env (later files override). CWD-only ".env" misses app/.env.
_ENV_FILES = tuple(
    str(p)
    for p in (_PROJECT_ROOT / ".env", _APP_DIR / ".env")
    if p.is_file()
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILES if _ENV_FILES else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "postgres"
    postgres_password: str = "123"
    postgres_db: str = "deep_proxy"

    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_hosts: str | None = Field(
        default=None,
        description="If set, overrides elasticsearch_url (same as ELASTICSEARCH_HOSTS in .env).",
    )
    elasticsearch_index: str = "proxy-logs"
    elasticsearch_username: str | None = None
    elasticsearch_password: str | None = None
    elasticsearch_verify_certs: bool = True
    elasticsearch_ca_certs: str | None = Field(
        default=None,
        description="Path to PEM bundle for verifying the cluster CA (when verify_certs is true).",
    )

    proxy_port: int = 9090
    dashboard_port: int = 8001

    max_body_storage_bytes: int = Field(
        default=1_048_576,
        description="Max bytes buffered from upstream response for logging; streaming still forwards the full body.",
    )
    max_incoming_request_body_bytes: int = Field(
        default=32 * 1024 * 1024,
        description="Max request body read from the client while parsing HTTP for plain proxy requests.",
    )

    # POST /api/ingest/flow — optional external log push. If set, require X-Deep-Proxy-Ingest-Token header.
    ingest_api_token: str | None = None

    proxy_user: str = ""
    proxy_pass: str = ""
    proxy_require_auth: bool = Field(
        default=True,
        description="When PROXY_USER and PROXY_PASS are set, require Basic Proxy-Authorization from clients.",
    )

    # Dashboard (Jinja2 + session cookie). Set admin_password and session_secret in production.
    admin_username: str = "admin"
    admin_password: str = ""
    session_secret: str = Field(
        default="change-me-generate-a-long-random-session-secret",
        description="Secret for signing session cookies (Starlette SessionMiddleware).",
    )

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def elasticsearch_node_url(self) -> str:
        return (self.elasticsearch_hosts or self.elasticsearch_url).rstrip("/")


@lru_cache
def get_settings() -> Settings:
    return Settings()
