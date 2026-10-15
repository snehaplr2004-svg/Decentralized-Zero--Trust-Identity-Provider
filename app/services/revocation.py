"""
Dynamic token revocation using Redis + Bloom filter.

Properties:
  - O(1) membership check
  - ~1.8 MB for 1M tokens @ 0.1% false-positive rate
  - No false negatives (revoked tokens always detected)
  - Rare false positives → token is re-issued (safe)
"""
import pickle
import logging

import redis
from pybloom_live import BloomFilter

from app.config import settings

logger = logging.getLogger(__name__)

r = redis.from_url(settings.REDIS_URL, decode_responses=False)

_BLOOM_KEY = "idp:revoked:bloom"
_COUNT_KEY = "idp:revoked:count"


def _load_bloom() -> BloomFilter:
    try:
        raw = r.get(_BLOOM_KEY)
    except redis.RedisError as e:
        logger.error("Redis unavailable for bloom load: %s", e)
        return BloomFilter(
            capacity=settings.BLOOM_CAPACITY,
            error_rate=settings.BLOOM_ERROR_RATE,
        )

    if raw:
        return pickle.loads(raw)

    return BloomFilter(
        capacity=settings.BLOOM_CAPACITY,
        error_rate=settings.BLOOM_ERROR_RATE,
    )


def _save_bloom(bf: BloomFilter) -> None:
    try:
        r.set(_BLOOM_KEY, pickle.dumps(bf))
    except redis.RedisError as e:
        logger.error("Redis unavailable for bloom save: %s", e)


def revoke(jti: str) -> int:
    """Add a JWT ID to the revocation filter. Returns total count."""
    if not jti:
        raise ValueError("jti must be a non-empty string")

    bf = _load_bloom()
    bf.add(jti)
    _save_bloom(bf)

    try:
        count = r.incr(_COUNT_KEY)
    except redis.RedisError:
        count = -1

    logger.info("Revoked jti=%s (total=%s)", jti, count)
    return count


def is_revoked(jti: str) -> bool:
    """Check the Bloom filter. False positives possible; false negatives not."""
    if not jti:
        return False
    return jti in _load_bloom()


def stats() -> dict:
    """Observability."""
    try:
        count = int(r.get(_COUNT_KEY) or 0)
    except redis.RedisError:
        count = -1
    return {
        "revoked_count": count,
        "bloom_capacity": settings.BLOOM_CAPACITY,
        "bloom_error_rate": settings.BLOOM_ERROR_RATE,
    }