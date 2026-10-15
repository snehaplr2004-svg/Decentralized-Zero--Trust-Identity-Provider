import pytest

from app.services import revocation


@pytest.fixture(autouse=True)
def clear_bloom():
    """Wipe the bloom filter before each test."""
    from app.services.revocation import r, _BLOOM_KEY, _COUNT_KEY
    try:
        r.delete(_BLOOM_KEY, _COUNT_KEY)
    except Exception:
        pytest.skip("Redis not available")


def test_revoke_and_check():
    jti = "test-jti-001"
    assert not revocation.is_revoked(jti)
    revocation.revoke(jti)
    assert revocation.is_revoked(jti)


def test_empty_jti_not_revoked():
    assert not revocation.is_revoked("")


def test_revoke_rejects_empty():
    with pytest.raises(ValueError):
        revocation.revoke("")