"""
Dynamic token revocation using Redis Bloom filter, with in-memory fallback.

When Redis is reachable, revocations are shared across the mesh.
When it isn't, we keep the Bloom filter in-process — perfect for local dev.
"""
import pickle
import logging
from threading import Lock

from pybloom_live import BloomFilter

from app.config import settings

logger = logging.getLogger(__name__)

# --- Try to connect to Redis; fall back to in-memory ---
_redis_client = None
try:
    import redis
    _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=False)
    _redis_client.ping()
    logger.info("Revocation: using Redis at %s", settings.REDIS_URL)
except Exception as e:
    logger.warning(
        "Revocation: Redis unavailable (%s), using in-memory filter", e
    )
    _redis_client = None

_BLOOM_KEY = "idp:revoked:bloom"
_COUNT_KEY = "idp:revoked:count"

# In-memory state (only used when Redis isn't reachable)
_mem_bloom = BloomFilter(
    capacity=settings.BLOOM_CAPACITY,
    error_rate=settings.BLOOM_ERROR_RATE,
)
_mem_count = 0
_lock = Lock()


def _load_bloom() -> BloomFilter:
    if _redis_client is None:
        return _mem_bloom
    try:
        raw = _redis_client.get(_BLOOM_KEY)
    except Exception as e:
        logger.error("Redis read failed: %s", e)
        return _mem_bloom
    if raw:
        return pickle.loads(raw)
    return BloomFilter(
        capacity=settings.BLOOM_CAPACITY,
        error_rate=settings.BLOOM_ERROR_RATE,
    )


def _save_bloom(bf: BloomFilter) -> None:
    if _redis_client is None:
        global _mem_bloom
        _mem_bloom = bf
        return
    try:
        _redis_client.set(_BLOOM_KEY, pickle.dumps(bf))
    except Exception as e:
        logger.error("Redis write failed: %s", e)


def revoke(jti: str) -> int:
    """Add a JWT ID to the revocation set. Returns total revoked count."""
    global _mem_count
    if not jti:
        raise ValueError("jti must be a non-empty string")

    with _lock:
        bf = _load_bloom()
        bf.add(jti)
        _save_bloom(bf)

        if _redis_client is None:
            _mem_count += 1
            logger.info("Revoked jti=%s (in-memory total=%s)", jti, _mem_count)
            return _mem_count

        try:
            count = _redis_client.incr(_COUNT_KEY)
        except Exception:
            count = -1
        logger.info("Revoked jti=%s (redis total=%s)", jti, count)
        return count


def is_revoked(jti: str) -> bool:
    """Check the Bloom filter. No false negatives; rare false positives."""
    if not jti:
        return False
    return jti in _load_bloom()


def stats() -> dict:
    """Observability: which backend is active + how many revoked."""
    if _redis_client is None:
        return {
            "backend": "in-memory",
            "revoked_count": _mem_count,
            "bloom_capacity": settings.BLOOM_CAPACITY,
            "bloom_error_rate": settings.BLOOM_ERROR_RATE,
        }
    try:
        count = int(_redis_client.get(_COUNT_KEY) or 0)
    except Exception:
        count = -1
    return {
        "backend": "redis",
        "revoked_count": count,
        "bloom_capacity": settings.BLOOM_CAPACITY,
        "bloom_error_rate": settings.BLOOM_ERROR_RATE,
    }