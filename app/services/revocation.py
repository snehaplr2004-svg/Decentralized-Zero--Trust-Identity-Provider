import redis
from pybloom_live import BloomFilter
import pickle

from app.config import settings

r = redis.from_url(settings.REDIS_URL)
_BLOOM_KEY = "idp:revoked_tokens"


def _load_bloom() -> BloomFilter:
    raw = r.get(_BLOOM_KEY)
    if raw:
        return pickle.loads(raw)
    return BloomFilter(capacity=settings.BLOOM_CAPACITY,
                       error_rate=settings.BLOOM_ERROR_RATE)


def _save_bloom(bf: BloomFilter) -> None:
    r.set(_BLOOM_KEY, pickle.dumps(bf))


def revoke(jti: str) -> None:
    bf = _load_bloom()
    bf.add(jti)
    _save_bloom(bf)


def is_revoked(jti: str) -> bool:
    return jti in _load_bloom()