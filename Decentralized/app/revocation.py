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


def revoke(jti: str, expires_at: int):
    ttl = max(1, expires_at - int(time.time()))
    client = get_redis()

    if client:
        client.setex(f"revoked:{jti}", ttl, "1")
    else:
        _local_revoked[jti] = expires_at


def is_revoked(jti: str):
    client = get_redis()

    if client:
        return bool(client.exists(f"revoked:{jti}"))

    now = int(time.time())
    for token_id, expiry in list(_local_revoked.items()):
        if expiry <= now:
            _local_revoked.pop(token_id, None)

    return jti in _local_revoked