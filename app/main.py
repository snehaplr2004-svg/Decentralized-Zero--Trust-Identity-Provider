from fastapi import FastAPI
from app.config import settings
from app.api import oidc, webauthn, ztna

app = FastAPI(title=settings.APP_NAME)

app.include_router(oidc.router)
app.include_router(webauthn.router, prefix="/webauthn", tags=["webauthn"])
app.include_router(ztna.router, prefix="/ztna", tags=["ztna"])


@app.get("/health")
async def health():
    return {"status": "ok", "issuer": settings.ISSUER}