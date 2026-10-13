import jwt
from fastapi import (
    FastAPI, HTTPException, Depends, Request
)

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
