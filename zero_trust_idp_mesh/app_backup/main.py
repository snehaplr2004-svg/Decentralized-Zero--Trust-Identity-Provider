
from fastapi import (
    FastAPI,
    HTTPException,
    Depends
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
from .policy import evaluate_risk
from .revocation import revocation_list

app = FastAPI(title="Zero-Trust IdP Mesh")

identities = {}


class IdentityRequest(BaseModel):
    subject: str = Field(min_length=2, max_length=120)


class TokenRequest(BaseModel):
    subject: str
    did: str
    ip_address: str = "127.0.0.1"
    device_posture: str = "compliant"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/identities")
def create_identity(payload: IdentityRequest):
    if payload.subject in identities:
        raise HTTPException(409, "Identity already exists")

    identity = create_did_identity(payload.subject)
    entry = ledger.anchor(identity["did"], identity["document"])

    identities[payload.subject] = identity

    return {
        "subject": payload.subject,
        "did": identity["did"],
        "document": identity["document"],
        "ledger_entry": entry
    }


@app.post("/token")
def create_token(payload: TokenRequest):
    identity = identities.get(payload.subject)

    if not identity or identity["did"] != payload.did:
        raise HTTPException(401, "Unknown identity")

    risk = evaluate_risk(
        payload.ip_address,
        payload.device_posture
    )

    if risk["decision"] != "allow":
        raise HTTPException(403, detail=risk)

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

@app.get("/ledger")
def show_ledger():
    return {
        "entries": ledger.list_entries()
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
