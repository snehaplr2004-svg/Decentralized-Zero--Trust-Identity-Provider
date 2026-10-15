"""
OpenID Connect / OAuth 2.0 endpoints + DID registration & resolution.
"""
from fastapi import APIRouter, Form, HTTPException

from app.config import settings
from app.core.security import create_access_token, server_public_pem
from app.ledger.blockchain import ledger
from app.models.schemas import (
    DIDRegisterRequest, DIDRegisterResponse,
)
from app.services.did_service import register_did, resolve_did

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


@router.get("/.well-known/jwks.json")
async def jwks():
    """Expose the server's public key. (Simplified JWKS.)"""
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "pem": server_public_pem(),
            }
        ]
    }


@router.post("/did/register", response_model=DIDRegisterResponse)
async def did_register(req: DIDRegisterRequest):
    return register_did()


@router.get("/did/{did:path}")
async def did_resolve(did: str):
    doc = resolve_did(did)
    if not doc:
        raise HTTPException(404, "DID not found on ledger")
    return doc


@router.get("/ledger/verify")
async def verify_ledger():
    return {"valid": ledger.verify(), "blocks": len(ledger.chain)}


@router.get("/ledger/chain")
async def get_chain():
    return {"chain": [b.to_dict() for b in ledger.chain]}


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