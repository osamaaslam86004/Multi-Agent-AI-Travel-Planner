"""
Unified Async HTTPX Client Factory with Connection Pooling and Lifecycle Integration.
"""

import logging

import httpx

from services.core.config import get_settings
from services.core.lifecycle.teardown import get_teardown_registry

logger = logging.getLogger("travelbrain.shared.http")

_http_client: httpx.AsyncClient | None = None


async def get_httpx_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        settings = get_settings()
        timeout = httpx.Timeout(settings.app.request_timeout_seconds, connect=5.0)
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        _http_client = httpx.AsyncClient(timeout=timeout, limits=limits)
        logger.info("Initialized unified async HTTPX client.")

        registry = get_teardown_registry()
        registry.register("httpx_client", close_httpx_client)

    return _http_client


async def close_httpx_client() -> None:
    global _http_client
    if _http_client is not None:
        try:
            await _http_client.aclose()
            logger.info("Closed unified async HTTPX client.")
        except (httpx.HTTPError, OSError, RuntimeError) as exc:
            logger.error(f"Error closing HTTPX client: {exc}")
        finally:
            _http_client = None
