
from cryptography.hazmat.primitives import serialization

from app.security import load_or_create_signing_key


def test_signing_key_survives_new_instance(tmp_path):
    key_path = tmp_path / "jwt_private.pem"

    # First load creates and saves the key.
    first_key = load_or_create_signing_key(key_path)

    # Second load reads the same saved key.
    second_key = load_or_create_signing_key(key_path)

    first_public_key = first_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    second_public_key = second_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    assert first_public_key == second_public_key
    assert key_path.exists()
