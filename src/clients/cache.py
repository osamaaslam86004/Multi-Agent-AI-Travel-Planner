# src/clients/cache.py
import functools
import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import redis

from src.config.settings import settings

logger = logging.getLogger(__name__)
_client: redis.Redis | None = None
_last_failure: float | None = None


def get_client() -> redis.Redis | None:
    global _client, _last_failure
    if not settings.redis.enabled or not settings.redis.url:
        return None
    if _client is not None:
        return _client
    now = time.monotonic()
    if (
        _last_failure is not None
        and now - _last_failure < settings.redis.reconnect_seconds
    ):
        return None
    try:
        client = redis.Redis.from_url(
            settings.redis.url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        _client = client
        _last_failure = None
        logger.info("Redis cache connected successfully.")
    except Exception as error:
        _client = None
        _last_failure = now
        logger.warning(
            "Redis cache unavailable (%s). Continuing without cache; will retry in %ss.",
            error,
            settings.redis.reconnect_seconds,
        )
    return _client


def drop_client() -> None:
    global _client, _last_failure
    _client = None
    _last_failure = time.monotonic()


def reset_client() -> None:
    global _client, _last_failure
    _client = None
    _last_failure = None


def status() -> dict:
    if not settings.redis.enabled or not settings.redis.url:
        return {
            "enabled": False,
            "connected": False,
            "reason": "Redis disabled or URL not set",
        }
    connected = get_client() is not None
    return {
        "enabled": True,
        "connected": connected,
    }


def build_key(prefix: str, args: tuple, kwargs: dict) -> str:
    fingerprint = json.dumps(
        [args, sorted(kwargs.items())], default=str, sort_keys=True
    )
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
    return f"{settings.redis.key_prefix}:{prefix}:{digest}"


def _read(key: str) -> tuple[bool, Any]:
    client = get_client()
    if client is None:
        return False, None
    try:
        payload = client.get(key)
    except Exception:
        drop_client()
        return False, None
    if payload is None:
        return False, None
    try:
        return True, json.loads(payload)
    except (TypeError, ValueError):
        return False, None


def _write(key: str, value: Any, ttl: int) -> Any:
    try:
        payload = json.dumps(value, default=str)
    except (TypeError, ValueError):
        return value
    client = get_client()
    if client is not None:
        try:
            client.setex(key, ttl, payload)
        except Exception:
            drop_client()
    return json.loads(payload)


def cached(prefix: str, ttl: int) -> Callable:
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = build_key(prefix, args, kwargs)
            hit, value = _read(key)
            if hit:
                return value
            return _write(key, func(*args, **kwargs), ttl)

        return wrapper

    return decorator


def async_cached(prefix: str, ttl: int) -> Callable:
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            key = build_key(prefix, args, kwargs)
            hit, value = _read(key)
            if hit:
                return value
            return _write(key, await func(*args, **kwargs), ttl)

        return wrapper

    return decorator
