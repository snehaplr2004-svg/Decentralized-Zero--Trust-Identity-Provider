ort json
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

from .config import WEBAUTHN_ORIGIN, WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME
from .database import connection, audit
from .security import create_access_token


class RegistrationVerifyBody(BaseModel):
    challenge_id: str
    credential: dict


class AuthenticationOptionsBody(BaseModel):
    username: str = Field(min_length=1, max_length=40)


class AuthenticationVerifyBody(BaseModel):
    challenge_id: str
    credential: dict


def create_webauthn_router(current_user_dependency):
    router = APIRouter(prefix="/webauthn", tags=["WebAuthn / FIDO2"])

    def save_challenge(user_id: int, purpose: str, challenge_bytes: bytes):
        challenge_id = secrets.token_urlsafe(24)
        expires_at = int(time.time()) + 300
        challenge_text = bytes_to_base64url(challenge_bytes)
        with connection() as db:
            db.execute(
                """INSERT INTO webauthn_challenges
                   (challenge_id, user_id, purpose, challenge, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (challenge_id, user_id, purpose, challenge_text, expires_at)
            )
        return challenge_id

    def get_valid_challenge(challenge_id: str, purpose: str):
        with connection() as db:
            row = db.execute(
                """SELECT * FROM webauthn_challenges
                   WHERE challenge_id = ? AND purpose = ?""",
                (challenge_id, purpose)
            ).fetchone()
        if row is None or row["expires_at"] < int(time.time()):
            raise HTTPException(400, "Challenge missing, expired, or already used")
        return dict(row)

    def consume_challenge(challenge_id: str):
        with connection() as db:
            db.execute(
                "DELETE FROM webauthn_challenges WHERE challenge_id = ?",
                (challenge_id,)
            )

    @router.post("/register/options")
    def registration_options(user=Depends(current_user_dependency)):
        with connection() as db:
            existing = db.execute(
                "SELECT credential_id FROM webauthn_credentials WHERE user_id = ?",
                (user["id"],)
            ).fetchall()

        options = generate_registration_options(
            rp_id=WEBAUTHN_RP_ID,
            rp_name=WEBAUTHN_RP_NAME,
            user_id=str(user["id"]).encode("utf-8"),
            user_name=user["username"],
            user_display_name=user["username"],
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(row["credential_id"])
                )
                for row in existing
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            ),
        )
        challenge_id = save_challenge(
            user["id"], "register", options.challenge
        )
        return {
            "challenge_id": challenge_id,
            "publicKey": json.loads(options_to_json(options)),
            "expires_in": 300,
            "note": "Send publicKey to navigator.credentials.create(); post its JSON result to /webauthn/register/verify."
        }