import logging

from elasticsearch import AsyncElasticsearch

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_client: AsyncElasticsearch | None = None


async def close_elasticsearch() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None


def get_elasticsearch() -> AsyncElasticsearch:
    global _client
    if _client is None:
        settings = get_settings()
        url = settings.elasticsearch_node_url
        kwargs: dict = {"hosts": [url]}
        if settings.elasticsearch_username is not None:
            kwargs["basic_auth"] = (
                settings.elasticsearch_username,
                settings.elasticsearch_password or "",
            )
        if not settings.elasticsearch_verify_certs:
            kwargs["verify_certs"] = False
            kwargs["ssl_show_warn"] = False
        elif settings.elasticsearch_ca_certs:
            kwargs["ca_certs"] = settings.elasticsearch_ca_certs
        _client = AsyncElasticsearch(**kwargs)
    return _client


async def ensure_index() -> None:
    """Create index if missing. Does not fail startup if Elasticsearch is down or misconfigured."""
    settings = get_settings()
    try:
        client = get_elasticsearch()
        index = settings.elasticsearch_index
        exists = await client.indices.exists(index=index)
        if exists:
            return
        await client.indices.create(
            index=index,
            settings={"number_of_shards": 1, "number_of_replicas": 0},
            mappings={
                "dynamic": True,
                "properties": {
                    "timestamp": {"type": "date"},
                    "method": {"type": "keyword"},
                    "url": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                    "client_ip": {"type": "keyword"},
                    "is_https": {"type": "boolean"},
                    "duration_ms": {"type": "float"},
                },
            },
        )
    except Exception as e:
        logger.warning(
            "Elasticsearch not reachable or index setup failed (%s). "
            "Dashboard search/logging to ES disabled until connection works. "
            "Use https:// + ELASTICSEARCH_USERNAME/PASSWORD if the cluster uses TLS/auth.",
            e,
        )
        await close_elasticsearch()
