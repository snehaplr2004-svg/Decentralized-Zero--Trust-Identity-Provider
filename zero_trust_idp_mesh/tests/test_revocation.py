
import time

from app.revocation import TokenRevocationList


def test_revocation_survives_new_instance(tmp_path):
    db_path = tmp_path / "test_revocations.db"

    # First instance saves the revoked token.
    first = TokenRevocationList(db_path=db_path)
    first.revoke("persistent-test-token", int(time.time()) + 60)

    # Second instance opens the same database.
    second = TokenRevocationList(db_path=db_path)

    assert second.is_revoked("persistent-test-token") is True


def test_expired_revocation_is_removed(tmp_path):
    db_path = tmp_path / "expired_revocations.db"

    revocations = TokenRevocationList(db_path=db_path)

    # This token expired in the past.
    revocations.revoke("expired-test-token", int(time.time()) - 10)

    assert revocations.is_revoked("expired-test-token") is False
