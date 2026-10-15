from fastapi import APIRouter, HTTPException, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import settings
from app.core.security import create_access_token
from app.core.did import create_did, build_did_document
from app.core.security import generate_ed25519_keypair
from app.ledger.blockchain import ledger

router = APIRouter(tags=["oidc"])


@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    return {
        "issuer": settings.ISSUER,
        "authorization_endpoint": f"{settings.BASE_URL}/authorize",
        "token_endpoint": f"{settings.BASE_URL}/token",
        "jwks_uri": f"{settings.BASE_URL}/.well-known/jwks.json",
        "response_types_supported": ["code", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "scopes_supported": ["openid", "profile", "email"],
    }


class DIDRegisterRequest(BaseModel):
    label: str | None = None


@router.post("/did/register")
async def register_did(req: DIDRegisterRequest):
    priv_pem, pub_pem = generate_ed25519_keypair()
    did = create_did(pub_pem)
    doc = build_did_document(did, pub_pem)
    block = ledger.anchor(doc)
    return {
        "did": did,
        "did_document": doc,
        "private_key_pem": priv_pem,   # client-side custody in real deploy
        "anchored_in_block": block.index,
        "block_hash": block.hash,
    }


@router.get("/did/{did:path}")
async def resolve_did(did: str):
    doc = ledger.get_did(did)
    if not doc:
        raise HTTPException(404, "DID not found on ledger")
    return doc


@router.get("/ledger/verify")
async def verify_ledger():
    return {"valid": ledger.verify(), "blocks": len(ledger.chain)}


@router.post("/token")
async def token_endpoint(
    grant_type: str = Form(...),
    subject: str = Form(...),
    did: str = Form(...),
):
    if grant_type != "authorization_code":
        raise HTTPException(400, "unsupported_grant_type")
    token = create_access_token(subject=subject, did=did)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": settings.JWT_EXPIRE_SECONDS,
    }