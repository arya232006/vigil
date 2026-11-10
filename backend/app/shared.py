"""State that must be shared when more than one API instance runs: rate limits and jobs, kept in Redis.

Optional. With REDIS_URL unset, rate limits and jobs stay in each process's memory, which is only correct for a single
API instance. The README says so.
"""
from __future__ import annotations

import functools
import hashlib
import logging
import os
import uuid

try:
    from redis.exceptions import RedisError
except ImportError:                                         # redis is only needed when REDIS_URL is set
    class RedisError(Exception):
        pass

log = logging.getLogger(__name__)

PREFIX = "vigil:"
WINDOW_MS = 60_000

# One atomic step per request, timed by the Redis server's clock, so instances with drifting clocks still agree.
_SLIDING_WINDOW = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - tonumber(ARGV[2]))
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
"""


@functools.lru_cache(maxsize=1)
def client():
    """The Redis client, or None when REDIS_URL is unset. Connecting happens on first use."""
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return None
    import redis
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2,
                                health_check_interval=30)


def key(*parts: str) -> str:
    return PREFIX + ":".join(parts)


def digest(value: str) -> str:
    """Keeps keys short and keeps raw emails and IPs out of Redis."""
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def allow(bucket: str, ident: str, limit: int, redis_client=None) -> bool | None:
    """True or False from the shared limiter, or None when there is no Redis or it can't be reached, so the caller
    falls back to its own per-process count instead of failing every request."""
    r = redis_client if redis_client is not None else client()
    if r is None:
        return None
    try:
        return bool(r.eval(_SLIDING_WINDOW, 1, key("rl", bucket, digest(ident)), limit, WINDOW_MS, uuid.uuid4().hex))
    except RedisError as e:
        log.warning("shared rate limit unavailable, using this process's count: %s", e)
        return None
