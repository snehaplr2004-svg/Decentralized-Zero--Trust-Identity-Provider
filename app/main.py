import json
import os
import time

import jwt
from fastapi import FastAPI, HTTPException, Depends, Request, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from .config import APP_NAME
from .database import init_db, connection, audit, get_logs, get_users
from .security import (
    hash_password, verify_password, generate_identity,
    create_access_token, decode_access_token,
)
from .ledger import add_block, load_chain, verify_chain
from .policy import evaluate_access
from .revocation import revoke, is_revoked
from .schemas import RegisterRequest, LoginRequest, AccessRequest

app = FastAPI(title=APP_NAME, version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer(auto_error=False)
templates = Jinja2Templates(directory="templates")

# WebAuthn configuration can be set in the environment. For local development,
# use localhost consistently in the browser URL and WEBAUTHN_ORIGIN.
RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.getenv("WEBAUTHN_RP_NAME", APP_NAME)
ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5500")
CHALLENGE_TTL = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))


@app.on_event("startup")
def startup():
    init_db()
    # Keep this change limited to main.py by creating WebAuthn tables here.
    with connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            transports TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS webauthn_challenges (
            username TEXT NOT NULL,
            purpose TEXT NOT NULL,
            challenge TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (username, purpose)
        )""")


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None:
        raise HTTPException(401, "Bearer token required")
    try:
        claims = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    jti = claims.get("jti", "")
    if jti and is_revoked(jti):
        raise HTTPException(401, "Token has been revoked")
    with connection() as db:
        row = db.execute(
            "SELECT id, username, email, did, public_key, role FROM users WHERE id = ?",
            (claims.get("sub"),),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "User no longer exists")
    return dict(row) | {"jti": jti, "exp": claims.get("exp")}


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin role required")
    return user


@app.get("/")
def home():
    return {"project": APP_NAME, "status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    try:
        valid = verify_chain()
    except Exception:
        valid = False
    return {"status": "healthy", "ledger_integrity": valid}


@app.post("/register", status_code=201)
def register(data: RegisterRequest):
    did, public_key, _private_key_demo = generate_identity()
    try:
        with connection() as db:
            cursor = db.execute(
                """INSERT INTO users
                   (username, email, password_hash, did, public_key, role, created_at)
                   VALUES (?, ?, ?, ?, ?, 'user', datetime('now'))""",
                (data.username, data.email, hash_password(data.password), did, public_key),
            )
            user_id = cursor.lastrowid
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(409, "Username or email already registered")
        raise
    try:
        add_block(did, public_key)
    except Exception:
        audit("ledger_error", data.username, {"did": did})
        raise HTTPException(500, "User created, but DID ledger anchoring failed")
    audit("registration", data.username, {"did": did})
    return {
        "message": "Registration successful", "user_id": user_id,
        "username": data.username, "did": did, "public_key": public_key,
    }


@app.post("/login")
def login(data: LoginRequest):
    with connection() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
    if user is None or not verify_password(data.password, user["password_hash"]):
        audit("login_failed", data.username, {})
        raise HTTPException(401, "Invalid username or password")
    token = create_access_token(user["id"], user["username"], user["role"])
    audit("login_success", data.username, {})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(user=Depends(current_user)):
    return {k: v for k, v in user.items() if k not in {"jti", "exp"}}


@app.post("/token/revoke")
def revoke_current_token(user=Depends(current_user)):
    expiry = user.get("exp")
    if hasattr(expiry, "timestamp"):
        expiry = int(expiry.timestamp())
    revoke(user["jti"], int(expiry or time.time() + 1800))
    audit("token_revoked", user["username"], {"jti": user["jti"]})
    return {"message": "Token revoked"}


@app.post("/access/check")
def access_check(data: AccessRequest, request: Request, user=Depends(current_user)):
    ip_address = request.client.host if request.client else ""
    # Keep the signature compatible with the existing policy.py.
    result = evaluate_access(
        authenticated=True, device_posture=data.device_posture,
        ip_address=ip_address, role=user["role"],
    )
    audit("access_" + result["decision"].lower(), user["username"], result)
    if result["decision"] == "BLOCK":
        raise HTTPException(403, detail=result)
    return result


def _find_did(did: str):
    for block in reversed(load_chain()):
        if block.get("did") == did:
            return block
    return None


@app.get("/did/resolve")
def did_resolve(did: str, user=Depends(current_user)):
    record = _find_did(did)
    if record is None:
        raise HTTPException(404, "DID not found")
    return {
        "did": did,
        "document": {"id": did, "verificationMethod": [{
            "id": f"{did}#key-1", "type": "Ed25519VerificationKey2020",
            "controller": did, "publicKey": record.get("public_key"),
        }]},
        "ledger_integrity": verify_chain(),
    }


@app.get("/did/verify")
def did_verify(did: str, user=Depends(current_user)):
    record = _find_did(did)
    return {"did": did, "found": record is not None,
            "ledger_integrity": verify_chain(), "record": record}


@app.get("/ledger")
def ledger(user=Depends(admin_user)):
    return {"valid": verify_chain(), "blocks": load_chain()}


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user=Depends(admin_user)):
    return templates.TemplateResponse(
        request=request, name="admin.html",
        context={"users": get_users(), "logs": get_logs(), "ledger_valid": verify_chain()},
    )


@app.get("/admin/api/logs")
def admin_logs(user=Depends(admin_user)):
    return {"logs": get_logs()}


@app.get("/.well-known/openid-configuration")
def discovery(request: Request):
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": base,
        "userinfo_endpoint": base + "/userinfo",
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "jwks_uri": base + "/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/.well-known/jwks.json")
def jwks():
    # Do not expose the shared HS256 signing secret. Full OIDC requires an
    # asymmetric ID-token signing key and a matching public JWKS.
    return {"keys": []}


@app.get("/userinfo")
def userinfo(user=Depends(current_user)):
    return {"sub": str(user["id"]), "preferred_username": user["username"],
            "email": user["email"], "did": user["did"]}


def _webauthn():
    try:
        from webauthn import (
            generate_registration_options, verify_registration_response,
            generate_authentication_options, verify_authentication_response,
        )
        from webauthn.helpers import (
            options_to_json, parse_registration_credential_json,
            parse_authentication_credential_json, base64url_to_bytes,
            bytes_to_base64url,
        )
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria, UserVerificationRequirement,
            PublicKeyCredentialDescriptor,
        )
        return locals()
    except ImportError:
        raise HTTPException(501, "Install WebAuthn support with: python -m pip install webauthn")


def _save_challenge(username: str, purpose: str, challenge: str):
    with connection() as db:
        db.execute(
            """INSERT INTO webauthn_challenges(username,purpose,challenge,expires_at)
               VALUES(?,?,?,?) ON CONFLICT(username,purpose) DO UPDATE SET
               challenge=excluded.challenge, expires_at=excluded.expires_at""",
            (username, purpose, challenge, int(time.time()) + CHALLENGE_TTL),
        )


def _consume_challenge(username: str, purpose: str):
    with connection() as db:
        row = db.execute(
            "SELECT challenge,expires_at FROM webauthn_challenges WHERE username=? AND purpose=?",
            (username, purpose),
        ).fetchone()
        db.execute("DELETE FROM webauthn_challenges WHERE username=? AND purpose=?", (username, purpose))
    if row is None or row["expires_at"] < int(time.time()):
        return None
    return row["challenge"]


@app.post("/webauthn/register/start")
def webauthn_register_start(user=Depends(current_user)):
    w = _webauthn()
    options = w["generate_registration_options"](
        rp_id=RP_ID, rp_name=RP_NAME, user_id=str(user["id"]).encode(),
        user_name=user["username"], user_display_name=user["username"],
        authenticator_selection=w["AuthenticatorSelectionCriteria"](
            user_verification=w["UserVerificationRequirement"].PREFERRED),
    )
    _save_challenge(user["username"], "registration", w["bytes_to_base64url"](options.challenge))
    return json.loads(w["options_to_json"](options))


@app.post("/webauthn/register/finish")
def webauthn_register_finish(credential: dict = Body(...), user=Depends(current_user)):
    w = _webauthn()
    challenge = _consume_challenge(user["username"], "registration")
    if not challenge:
        raise HTTPException(400, "Missing or expired WebAuthn challenge")
    try:
        parsed = w["parse_registration_credential_json"](json.dumps(credential))
        result = w["verify_registration_response"](
            credential=parsed, expected_challenge=w["base64url_to_bytes"](challenge),
            expected_rp_id=RP_ID, expected_origin=ORIGIN, require_user_verification=False,
        )
    except Exception as exc:
        print("WebAuthn registration error:", repr(exc))
        audit("webauthn_registration_failed", user["username"], {
            "error": repr(exc)
        })
        raise HTTPException(
            400,
            "WebAuthn registration verification failed: " + str(exc)
        )

    credential_id = w["bytes_to_base64url"](result.credential_id)
    public_key = w["bytes_to_base64url"](result.credential_public_key)
    transports = credential.get("response", {}).get("transports", [])
    try:
        with connection() as db:
            db.execute(
                """INSERT INTO webauthn_credentials
                   (user_id,credential_id,public_key,sign_count,transports)
                   VALUES(?,?,?,?,?)""",
                (user["id"], credential_id, public_key, result.sign_count, json.dumps(transports)),
            )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(409, "Credential already registered")
        raise
    audit("webauthn_registered", user["username"], {})
    return {"verified": True, "message": "WebAuthn credential registered"}


@app.post("/webauthn/login/start")
def webauthn_login_start(user=Depends(current_user)):
    w = _webauthn()
    with connection() as db:
        rows = db.execute("SELECT credential_id FROM webauthn_credentials WHERE user_id=?", (user["id"],)).fetchall()
    if not rows:
        raise HTTPException(404, "No WebAuthn credential registered")
    descriptors = [w["PublicKeyCredentialDescriptor"](id=w["base64url_to_bytes"](r["credential_id"])) for r in rows]
    options = w["generate_authentication_options"](
        rp_id=RP_ID, allow_credentials=descriptors,
        user_verification=w["UserVerificationRequirement"].PREFERRED,
    )
    _save_challenge(user["username"], "authentication", w["bytes_to_base64url"](options.challenge))
    return json.loads(w["options_to_json"](options))


@app.post("/webauthn/login/finish")
def webauthn_login_finish(credential: dict = Body(...), user=Depends(current_user)):
    w = _webauthn()
    challenge = _consume_challenge(user["username"], "authentication")
    if not challenge:
        raise HTTPException(400, "Missing or expired WebAuthn challenge")
    credential_id = credential.get("id")
    if not credential_id:
        raise HTTPException(400, "Credential ID is missing")
    with connection() as db:
        row = db.execute(
            "SELECT * FROM webauthn_credentials WHERE user_id=? AND credential_id=?",
            (user["id"], credential_id),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "Unknown WebAuthn credential")
    try:
        parsed = w["parse_authentication_credential_json"](json.dumps(credential))
        result = w["verify_authentication_response"](
            credential=parsed, expected_challenge=w["base64url_to_bytes"](challenge),
            expected_rp_id=RP_ID, expected_origin=ORIGIN,
            credential_public_key=w["base64url_to_bytes"](row["public_key"]),
            credential_current_sign_count=row["sign_count"], require_user_verification=False,
        )
    except Exception:
        audit("webauthn_login_failed", user["username"], {})
        raise HTTPException(401, "WebAuthn authentication verification failed")
    with connection() as db:
        db.execute("UPDATE webauthn_credentials SET sign_count=? WHERE id=?", (result.new_sign_count, row["id"]))
    token = create_access_token(user["id"], user["username"], user["role"])
    audit("webauthn_login_success", user["username"], {})
    return {"verified": True, "access_token": token, "token_type": "bearer"}


@app.get("/oauth/authorize")
def oauth_authorize():
    raise HTTPException(501, "OIDC authorization-code flow is not implemented yet")


@app.post("/oauth/token")
def oauth_token():
    raise HTTPException(501, "OIDC token exchange is not implemented yet")