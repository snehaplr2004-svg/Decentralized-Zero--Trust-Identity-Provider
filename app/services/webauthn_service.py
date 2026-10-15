from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)
from app.config import settings

# In-memory credential store; swap for Postgres/Redis in prod
CREDENTIALS: dict[str, dict] = {}    # did -> credential record
CHALLENGES: dict[str, bytes] = {}    # did -> challenge


def reg_options(did: str, username: str):
    opts = generate_registration_options(
        rp_id=settings.RP_ID,
        rp_name=settings.RP_NAME,
        user_id=did.encode(),
        user_name=username,
    )
    CHALLENGES[did] = opts.challenge
    return opts


def reg_verify(did: str, credential: dict):
    expected = CHALLENGES.pop(did, None)
    if expected is None:
        raise ValueError("No pending challenge")
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected,
        expected_rp_id=settings.RP_ID,
        expected_origin=settings.ORIGIN,
    )
    CREDENTIALS[did] = {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    }
    return verification


def auth_options(did: str):
    cred = CREDENTIALS.get(did)
    if not cred:
        raise ValueError("DID not registered")
    opts = generate_authentication_options(
        rp_id=settings.RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cred["credential_id"])],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    CHALLENGES[did] = opts.challenge
    return opts


def auth_verify(did: str, credential: dict):
    expected = CHALLENGES.pop(did, None)
    if expected is None:
        raise ValueError("No pending challenge")
    cred = CREDENTIALS[did]
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected,
        expected_rp_id=settings.RP_ID,
        expected_origin=settings.ORIGIN,
        credential_public_key=cred["public_key"],
        credential_current_sign_count=cred["sign_count"],
    )
    CREDENTIALS[did]["sign_count"] = verification.new_sign_count
    return verification