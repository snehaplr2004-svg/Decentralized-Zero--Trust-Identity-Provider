import time
from .config import REDIS_URL
_local_revoked = {}
_redis = None


def get_redis():
    global _redis

    if _redis is None:
        try:
            import redis
            client = redis.Redis.from_url(
                REDIS_URL, decode_responses=True,
                socket_connect_timeout=1
            )
            client.ping()
            _redis = client
        except Exception:
            _redis = False

    return _redis if _redis is not False else None