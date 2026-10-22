@router.post("/register/verify")
    def registration_verify(
        body: RegistrationVerifyBody,
        user=Depends(current_user_dependency)
    ):
        challenge = get_valid_challenge(body.challenge_id, "register")
        if challenge["user_id"] != user["id"]:
            raise HTTPException(403, "Challenge does not belong to this user")

        try:
            verification = verify_registration_response(
                credential=body.credential,
                expected_challenge=base64url_to_bytes(challenge["challenge"]),
                expected_rp_id=WEBAUTHN_RP_ID,
                expected_origin=WEBAUTHN_ORIGIN,
                require_user_verification=False,
            )
        except Exception as exc:
            consume_challenge(body.challenge_id)
            raise HTTPException(400, "WebAuthn registration verification failed") from exc

        credential_id = bytes_to_base64url(verification.credential_id)
        transports = body.credential.get("response", {}).get("transports", [])
        with connection() as db:
            try:
                db.execute(
                    """INSERT INTO webauthn_credentials
                       (user_id, credential_id, public_key, sign_count, transports)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        user["id"], credential_id,
                        verification.credential_public_key,
                        verification.sign_count, json.dumps(transports)
                    )
                )
            except Exception as exc:
                raise HTTPException(409, "Credential is already registered") from exc

        consume_challenge(body.challenge_id)
        audit("webauthn_registered", user["username"], {"credential_id": credential_id})
        return {"message": "WebAuthn credential registered", "credential_id": credential_id}

    @router.post("/auth/options")
    def authentication_options(body: AuthenticationOptionsBody):
        with connection() as db:
            user_row = db.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (body.username,)
            ).fetchone()
            if user_row is None:
                raise HTTPException(401, "Unable to authenticate with WebAuthn")
            credentials = db.execute(
                """SELECT credential_id FROM webauthn_credentials
                   WHERE user_id = ?""",
                (user_row["id"],)
            ).fetchall()

        if not credentials:
            raise HTTPException(401, "Unable to authenticate with WebAuthn")

        options = generate_authentication_options(
            rp_id=WEBAUTHN_RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(row["credential_id"])
                )
                for row in credentials
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        challenge_id = save_challenge(
            user_row["id"], "authenticate", options.challenge
        )
        return {
            "challenge_id": challenge_id,
            "publicKey": json.loads(options_to_json(options)),
            "expires_in": 300,
            "note": "Send publicKey to navigator.credentials.get(); post its JSON result to /webauthn/auth/verify."
        }

    @router.post("/auth/verify")
    def authentication_verify(body: AuthenticationVerifyBody):
        challenge = get_valid_challenge(body.challenge_id, "authenticate")
        credential_id = body.credential.get("id", "")
        with connection() as db:
            credential = db.execute(
                """SELECT c.*, u.id AS account_id, u.username, u.role
                   FROM webauthn_credentials c
                   JOIN users u ON u.id = c.user_id
                   WHERE c.credential_id = ? AND c.user_id = ?""",
                (credential_id, challenge["user_id"])
            ).fetchone()

        if credential is None:
            consume_challenge(body.challenge_id)
            raise HTTPException(401, "Unable to authenticate with WebAuthn")

        try:
            verification = verify_authentication_response(
                credential=body.credential,
                expected_challenge=base64url_to_bytes(challenge["challenge"]),
                expected_rp_id=WEBAUTHN_RP_ID,
                expected_origin=WEBAUTHN_ORIGIN,
                credential_public_key=bytes(credential["public_key"]),
                credential_current_sign_count=credential["sign_count"],
                require_user_verification=False,
            )
        except Exception as exc:
            consume_challenge(body.challenge_id)
            audit("webauthn_login_failed", credential["username"], {})
            raise HTTPException(401, "WebAuthn authentication failed") from exc

        with connection() as db:
            db.execute(
                """UPDATE webauthn_credentials SET sign_count = ?
                   WHERE credential_id = ?""",
                (verification.new_sign_count, credential_id)
            )

        consume_challenge(body.challenge_id)
        token = create_access_token(
            credential["account_id"], credential["username"], credential["role"]
        )
        audit("webauthn_login_success", credential["username"], {})
        return {"access_token": token, "token_type": "bearer"}

    return router