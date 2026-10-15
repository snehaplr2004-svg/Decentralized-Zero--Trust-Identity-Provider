
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
