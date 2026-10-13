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