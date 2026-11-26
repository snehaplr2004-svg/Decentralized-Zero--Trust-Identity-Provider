
import re

import jwt

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Query
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

from pydantic import BaseModel, Field

from .security import (
    create_did_identity,
    issue_access_token,
    VERIFY_KEY
)

from .ledger import ledger
from .identity_store import identity_registry
from .policy import evaluate_risk
from .revocation import revocation_list
from .mfa import mfa_service
from .config import settings
from .email_service import send_otp_email


app = FastAPI(title="Zero-Trust IdP Mesh")


# --------------------------------------------------
# Request models
# --------------------------------------------------

class IdentityRequest(BaseModel):
    subject: str = Field(min_length=2, max_length=120)
    email: str | None = Field(default=None, max_length=254)


class TokenRequest(BaseModel):
    subject: str
    did: str
    ip_address: str = "127.0.0.1"
    device_posture: str = "compliant"


class MFAVerificationRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    otp: str = Field(pattern=r"^\d{6}$")


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.environment
    }


# --------------------------------------------------
# Create a new DID identity
# --------------------------------------------------

@app.post("/identities")
def create_identity(payload: IdentityRequest):

    email = payload.email

    if email is not None:
        email = email.strip().lower()

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):
            raise HTTPException(
                status_code=422,
                detail="A valid email address is required"
            )

    if settings.is_production and not email:
        raise HTTPException(
            status_code=422,
            detail="An email address is required for production identity registration"
        )

    identity = create_did_identity(payload.subject)

    # Preserve compatibility with existing callers and tests
    # that register identities without an email.
    if email is None:
        entry = identity_registry.register_identity_with_ledger(
            payload.subject,
            identity
        )
    else:
        entry = identity_registry.register_identity_with_ledger(
            payload.subject,
            identity,
            email=email
        )

    if entry is None:
        raise HTTPException(
            status_code=409,
            detail="Identity already exists"
        )

    return {
        "subject": payload.subject,
        "did": identity["did"],
        "document": identity["document"],
        "ledger_entry": entry
    }


# --------------------------------------------------
# Generate an access token or request MFA
# --------------------------------------------------

@app.post("/token")
def create_token(payload: TokenRequest):

    identity = identity_registry.get_identity(
        payload.subject
    )

    if not identity or identity["did"] != payload.did:
        raise HTTPException(
            status_code=401,
            detail="Unknown identity"
        )

    risk = evaluate_risk(
        payload.ip_address,
        payload.device_posture
    )

    # Reject high-risk login attempts.
    if risk["decision"] == "deny":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Access denied by risk policy",
                "risk": risk
            }
        )

    # Require MFA for medium-risk login attempts.
    if risk["decision"] == "step_up":

        email_delivery_required = (
            settings.is_production
            or settings.email_mfa_enabled
        )

        recipient = identity.get("email")

        if email_delivery_required:

            if not recipient:
                raise HTTPException(
                    status_code=409,
                    detail="This identity has no registered email address for MFA"
                )

            if not settings.smtp_configured:
                raise HTTPException(
                    status_code=503,
                    detail="Email MFA is not configured"
                )

        elif not settings.expose_development_otp:
            raise HTTPException(
                status_code=503,
                detail="MFA delivery is not configured"
            )

        challenge = mfa_service.create_challenge(
            payload.subject,
            payload.did
        )

        if email_delivery_required:

            try:
                send_otp_email(
                    recipient,
                    challenge["otp"]
                )

            except Exception:
                # Remove the challenge if delivery fails.
                mfa_service.discard_challenge(
                    challenge["challenge_id"]
                )

                raise HTTPException(
                    status_code=503,
                    detail="Unable to deliver verification email. Please try again."
                )

        response = {
            "message": "Additional verification required",
            "mfa_required": True,
            "challenge_id": challenge["challenge_id"],
            "otp_expiry_seconds": mfa_service.otp_expiry_seconds,
            "risk": risk
        }

        # Development-only OTP exposure.
        # Never expose OTP when email delivery is used.
        if (
            not email_delivery_required
            and settings.expose_development_otp
        ):
            response["development_otp"] = challenge["otp"]

        return response

    # Issue token for low-risk login attempts.
    token = issue_access_token(
        payload.subject,
        payload.did,
        ["openid", "profile"],
        risk
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "mfa_required": False,
        "risk": risk
    }


# --------------------------------------------------
# Verify OTP and issue JWT
# --------------------------------------------------

@app.post("/mfa/verify")
def verify_mfa(payload: MFAVerificationRequest):

    result = mfa_service.verify_challenge(
        payload.challenge_id,
        payload.otp
    )

    if not result["valid"]:
        raise HTTPException(
            status_code=401,
            detail=result
        )

    verified_risk = {
        "decision": "allow",
        "step_up_required": True,
        "mfa_verified": True
    }

    token = issue_access_token(
        result["subject"],
        result["did"],
        ["openid", "profile"],
        verified_risk
    )

    return {
        "message": "MFA verification successful",
        "access_token": token,
        "token_type": "Bearer",
        "mfa_verified": True
    }


# --------------------------------------------------
# Retrieve ledger entries with pagination
# --------------------------------------------------

@app.get("/ledger")
def show_ledger(
    skip: int = 0,
    limit: int = 10
):

    if skip < 0:
        raise HTTPException(
            status_code=400,
            detail="Skip cannot be negative"
        )

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100"
        )

    return ledger.list_entries_paginated(
        skip=skip,
        limit=limit
    )


# --------------------------------------------------
# Verify complete ledger integrity
# --------------------------------------------------

@app.get("/ledger/verify")
def verify_ledger():

    return ledger.verify_chain()


# --------------------------------------------------
# Search ledger entries using DID
# --------------------------------------------------

@app.get("/ledger/search")
def search_ledger_by_did(
    did: str = Query(
        ...,
        min_length=1,
        max_length=512
    )
):

    did = did.strip()

    if not did:
        raise HTTPException(
            status_code=400,
            detail="DID cannot be empty"
        )

    entries = ledger.search_by_did(did)

    return {
        "did": did,
        "total_entries": len(entries),
        "entries": entries
    }


# --------------------------------------------------
# Retrieve one ledger entry by ID
# --------------------------------------------------

@app.get("/ledger/{entry_id}")
def get_ledger_entry(entry_id: int):

    entry = ledger.get_entry(entry_id)

    if entry is None:
        raise HTTPException(
            status_code=404,
            detail="Ledger entry not found"
        )

    return {
        "message": "Ledger entry retrieved successfully",
        "entry": entry
    }


# --------------------------------------------------
# JWT authentication
# --------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)


def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    )
):

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Bearer token required"
        )

    try:
        claims = jwt.decode(
            credentials.credentials,
            VERIFY_KEY,
            algorithms=["EdDSA"],
            issuer="http://localhost:8000",
            audience="idp-mesh-api"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    if revocation_list.is_revoked(claims["jti"]):
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked"
        )

    return claims


# --------------------------------------------------
# Logout endpoint
# --------------------------------------------------

@app.post("/logout")
def logout(claims: dict = Depends(validate_token)):

    revocation_list.revoke(
        claims["jti"],
        claims["exp"]
    )

    return {
        "message": "Logout successful",
        "token_revoked": True
    }


# --------------------------------------------------
# Protected endpoint
# --------------------------------------------------

@app.get("/protected")
def protected_route(
    claims: dict = Depends(validate_token)
):

    return {
        "message": "Access granted",
        "subject": claims["sub"],
        "did": claims["did"]
    }
