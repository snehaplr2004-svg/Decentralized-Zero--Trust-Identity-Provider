
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .security import create_did_identity, issue_access_token
from .ledger import ledger
from .policy import evaluate_risk

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
