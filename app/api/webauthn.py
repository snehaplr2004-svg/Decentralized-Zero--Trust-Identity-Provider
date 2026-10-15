"""WebAuthn (FIDO2) registration and authentication routes."""
from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    RegBegin, RegComplete, AuthBegin, AuthComplete,
)
from app.services import webauthn_service as wsvc

router = APIRouter()


@router.post("/register/begin")
async def register_begin(req: RegBegin):
    opts = wsvc.reg_options(req.did, req.username)
    return {"options": opts}


@router.post("/register/complete")
async def register_complete(req: RegComplete):
    try:
        v = wsvc.reg_verify(req.did, req.credential)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"verified": True, "credential_id": v.credential_id.hex()}


@router.post("/authenticate/begin")
async def auth_begin(req: AuthBegin):
    try:
        opts = wsvc.auth_options(req.did)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"options": opts}


@router.post("/authenticate/complete")
async def auth_complete(req: AuthComplete):
    try:
        v = wsvc.auth_verify(req.did, req.credential)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"verified": True, "new_sign_count": v.new_sign_count}