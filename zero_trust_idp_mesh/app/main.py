
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
import jwt

from .security import (
    create_did_identity,
    issue_access_token,
    VERIFY_KEY
)

from .ledger import ledger
from .identity_store import identity_registry
from .policy import evaluate_risk
from .revocation import revocation_list


app = FastAPI(title="Zero-Trust IdP Mesh")


# Request models
class IdentityRequest(BaseModel):
    subject: str = Field(min_length=2, max_length=120)


class TokenRequest(BaseModel):
    subject: str
    did: str
    ip_address: str = "127.0.0.1"
    device_posture: str = "compliant"


# Health check endpoint
@app.get("/health")
def health():
    return {
        "status": "ok"
    }


# Create a new DID identity
@app.post("/identities")
def create_identity(payload: IdentityRequest):

    identity = create_did_identity(payload.subject)

    entry = identity_registry.register_identity_with_ledger(
        payload.subject,
        identity
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


# Generate an access token
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

    if risk["decision"] != "allow":
        raise HTTPException(
            status_code=403,
            detail=risk
        )

    token = issue_access_token(
        payload.subject,
        payload.did,
        ["openid", "profile"],
        risk
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "risk": risk
    }


# Retrieve ledger entries with pagination
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


# Verify complete ledger integrity
@app.get("/ledger/verify")
def verify_ledger():

    return ledger.verify_chain()


# Search ledger entries using DID
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


# Retrieve one ledger entry by ID
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


# JWT authentication
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


# Logout endpoint
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


# Protected endpoint
@app.get("/protected")
def protected_route(
    claims: dict = Depends(validate_token)
):

    return {
        "message": "Access granted",
        "subject": claims["sub"],
        "did": claims["did"]
    }
