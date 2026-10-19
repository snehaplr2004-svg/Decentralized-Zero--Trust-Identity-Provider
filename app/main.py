import secrets
import time

import jwt
from fastapi import (
    FastAPI, HTTPException, Depends, Request
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .config import APP_NAME
from .database import (
    init_db, connection, audit, get_logs, get_users
)
from .security import (
    hash_password, verify_password, generate_identity,
    create_access_token, decode_access_token
)
from .ledger import add_block, load_chain, verify_chain
from .policy import evaluate_access
from .revocation import revoke, is_revoked
from .schemas import RegisterRequest, LoginRequest, AccessRequest

app = FastAPI(title=APP_NAME, version="1.0.0")
bearer = HTTPBearer(auto_error=False)
templates = Jinja2Templates(directory="templates")

# Educational challenge store only. This is not a real WebAuthn
# credential store or cryptographic authenticator verification.
webauthn_challenges = {}


@app.on_event("startup")
def startup():
    init_db()


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer)
):
    if credentials is None:
        raise HTTPException(401, "Bearer token required")

    try:
        claims = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")

    if is_revoked(claims.get("jti", "")):
        raise HTTPException(401, "Token has been revoked")

    with connection() as db:
        user = db.execute(
            """SELECT id, username, email, did, public_key, role
               FROM users WHERE id = ?""",
            (claims.get("sub"),)
        ).fetchone()

    if user is None:
        raise HTTPException(401, "User no longer exists")

    return dict(user) | {"jti": claims["jti"]}


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin role required")
    return user


@app.get("/")
def home():
    return {
        "project": APP_NAME,
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/register", status_code=201)
def register(data: RegisterRequest):
    did, public_key, _private_key_demo = generate_identity()

    try:
        with connection() as db:
            cursor = db.execute(
                """INSERT INTO users
                   (username, email, password_hash, did,
                    public_key, role, created_at)
                   VALUES (?, ?, ?, ?, ?, 'user', datetime('now'))""",
                (
                    data.username, data.email,
                    hash_password(data.password),
                    did, public_key
                )
            )
            user_id = cursor.lastrowid
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(
                409, "Username or email already registered"
            )
        raise

    try:
        add_block(did, public_key)
    except Exception:
        # Avoid silently claiming ledger anchoring succeeded.
        audit("ledger_error", data.username, {"did": did})
        raise HTTPException(
            500, "User created, but ledger anchoring failed; inspect logs"
        )

    audit("registration", data.username, {"did": did})

    return {
        "message": "Registration successful",
        "user_id": user_id,
        "username": data.username,
        "did": did,
        "public_key": public_key
    }


@app.post("/login")
def login(data: LoginRequest):
    with connection() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()

    if user is None or not verify_password(
        data.password, user["password_hash"]
    ):
        audit("login_failed", data.username, {})
        raise HTTPException(401, "Invalid username or password")

    token = create_access_token(
        user["id"], user["username"], user["role"]
    )
    audit("login_success", data.username, {})

    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(user=Depends(current_user)):
    return user


@app.post("/token/revoke")
def revoke_current_token(user=Depends(current_user)):
    # The JWT is already validated by current_user.
    with connection() as db:
        row = db.execute(
            "SELECT id FROM users WHERE id = ?", (user["id"],)
        ).fetchone()

    # Get expiry from the original token claims by using the
    # authenticated token's jti and a conservative maximum TTL.
    # Tokens in this demo expire after 30 minutes.
    revoke(user["jti"], int(time.time()) + 1800)

    audit("token_revoked", user["username"], {"jti": user["jti"]})
    return {"message": "Token revoked"}


@app.post("/access/check")
def access_check(
    data: AccessRequest,
    request: Request,
    user=Depends(current_user)
):
    ip_address = request.client.host if request.client else ""

    result = evaluate_access(
        authenticated=True,
        device_posture=data.device_posture,
        ip_address=ip_address,
        role=user["role"]
    )

    audit(
        "access_" + result["decision"].lower(),
        user["username"],
        result
    )

    if result["decision"] == "BLOCK":
        raise HTTPException(
            403,
            detail=result
        )

    return result


@app.get("/did/verify")
def did_verify(did: str, user=Depends(current_user)):
    chain = load_chain()
    found = next(
        (block for block in chain if block["did"] == did),
        None
    )

    return {
        "did": did,
        "found": found is not None,
        "ledger_integrity": verify_chain(),
        "record": found
    }


@app.get("/ledger")
def ledger(user=Depends(admin_user)):
    return {
        "valid": verify_chain(),
        "blocks": load_chain()
    }


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user=Depends(admin_user)
):
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "users": get_users(),
            "logs": get_logs()
        }
    )


@app.get("/.well-known/openid-configuration")
def discovery(request: Request):
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": base,
        "userinfo_endpoint": base + "/userinfo",
        "token_endpoint": base + "/login",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["token"]
    }


@app.get("/userinfo")
def userinfo(user=Depends(current_user)):
    return {
        "sub": str(user["id"]),
        "preferred_username": user["username"],
        "email": user["email"],
        "did": user["did"]
    }


@app.post("/webauthn/auth/start")
def webauthn_start(user=Depends(current_user)):
    challenge = secrets.token_urlsafe(32)
    webauthn_challenges[user["username"]] = {
        "challenge": challenge,
        "expires": int(time.time()) + 300
    }
    return {
        "challenge": challenge,
        "expires_in": 300,
        "note": "Educational challenge demo, not FIDO2 verification"
    }


@app.get("/admin/api/logs")
def admin_logs(user=Depends(admin_user)):
    return {"logs": get_logs()}