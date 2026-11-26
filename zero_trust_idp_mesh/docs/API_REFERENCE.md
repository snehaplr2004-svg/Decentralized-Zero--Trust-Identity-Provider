# API Reference
## Decentralized Zero-Trust Identity Provider Mesh

Base URL: `http://127.0.0.1:8000`

Interactive API documentation: `http://127.0.0.1:8000/docs`

---

## 1. Health Check

### GET `/health`

Checks whether the application is running.

**Successful response: 200 OK**

```json
{
  "status": "ok",
  "environment": "development"
}
```

---

## 2. Register Identity

### POST `/identities`

Registers a new identity and generates a Decentralized Identifier (DID).

**Request body:**

```json
{
  "subject": "jeevan_test",
  "email": "user@example.com"
}
```

The email field is optional in development and required in production.

**Successful response: 200 OK**

Returns:
- Registered subject.
- Generated DID.
- DID document.
- Corresponding ledger entry.

**Possible errors:**

| Status | Description |
|---|---|
| 409 | Identity already exists |
| 422 | Invalid request or missing production email |

---

## 3. Request Access Token

### POST `/token`

Authenticates an existing identity and evaluates its access risk.

**Request body:**

```json
{
  "subject": "jeevan_test",
  "did": "did:key:YOUR_DID",
  "ip_address": "127.0.0.1",
  "device_posture": "compliant"
}
```

**Possible outcomes:**

| Decision | Result |
|---|---|
| Allow | Access token issued |
| Step-up | Additional MFA verification required |
| Deny | Access rejected |

When email MFA is enabled, an OTP is sent to the registered email address.

**Successful response for normal access: 200 OK**

Returns:
- Access token.
- Token type.
- MFA status.
- Risk evaluation.

**Successful response for step-up authentication: 200 OK**

Returns:
- MFA required status.
- Challenge ID.
- OTP expiry.
- Risk evaluation.

The OTP is not exposed in the API response when email delivery is used.

**Possible errors:**

| Status | Description |
|---|---|
| 401 | Unknown identity |
| 403 | Access denied by risk policy |
| 409 | No registered email for MFA |
| 503 | Email MFA configuration or delivery failure |

---

## 4. Verify Multi-Factor Authentication

### POST `/mfa/verify`

Verifies the six-digit OTP associated with an MFA challenge.

**Request body:**

```json
{
  "challenge_id": "YOUR_CHALLENGE_ID",
  "otp": "123456"
}
```

**Successful response: 200 OK**

```json
{
  "message": "MFA verification successful",
  "access_token": "YOUR_ACCESS_TOKEN",
  "token_type": "Bearer",
  "mfa_verified": true
}
```

**Security controls:**

- Six-digit OTP.
- Five-minute expiration.
- Maximum five verification attempts.
- One-time OTP usage.
- SHA-256 OTP hash storage.

**Possible errors:**

| Status | Description |
|---|---|
| 401 | Invalid, expired, or exhausted MFA challenge |
| 422 | Invalid request format |

---

## 5. Protected Resource

### GET `/protected`

Provides access to a protected resource after successful authentication.

**Authentication:**

Use a Bearer access token.

```text
Authorization: Bearer YOUR_ACCESS_TOKEN
```

**Successful response: 200 OK**

Returns:
- Access granted message.
- Authenticated subject.
- Associated DID.

**Possible errors:**

| Status | Description |
|---|---|
| 401 | Missing, invalid, expired, or revoked token |

---

## 6. Logout

### POST `/logout`

Revokes the currently authenticated JWT.

**Authentication:**

Requires a valid Bearer access token.

**Successful response: 200 OK**

```json
{
  "message": "Logout successful",
  "token_revoked": true
}
```

After logout, the same token cannot access protected resources.

Expected response after revocation: `401 Unauthorized`.

---

## 7. Retrieve Ledger Entries

### GET `/ledger`

Retrieves identity ledger entries with pagination.

**Query parameters:**

| Parameter | Description | Default |
|---|---|---|
| skip | Number of entries to skip | 0 |
| limit | Maximum entries to retrieve (1–100) | 10 |

Example:

```text
GET /ledger?skip=0&limit=10
```

**Successful response: 200 OK**

Returns the requested ledger entries.

---

## 8. Verify Ledger Integrity

### GET `/ledger/verify`

Verifies the integrity of the SHA-256 hash-chain ledger.

**Successful response: 200 OK**

Example:

```json
{
  "valid": true,
  "total_entries": 14,
  "checked_entries": 14,
  "failed_entry": null,
  "reason": null,
  "message": "Ledger integrity verified successfully"
}
```

The values above are an example of a previously observed verification result, not a fixed response.

---

## 9. Search Ledger by DID

### GET `/ledger/search`

Searches ledger records associated with a specific DID.

**Query parameter:**

`did` — DID to search for.

Example:

```text
GET /ledger/search?did=did:key:YOUR_DID
```

**Successful response: 200 OK**

Returns:
- Requested DID.
- Total matching entries.
- Matching ledger entries.

---

## 10. Retrieve Ledger Entry

### GET `/ledger/{entry_id}`

Retrieves a specific ledger entry by its numeric ID.

Example:

```text
GET /ledger/1
```

**Successful response: 200 OK**

Returns the requested ledger entry.

**Possible errors:**

| Status | Description |
|---|---|
| 404 | Ledger entry not found |

---

## Authentication and Security Notes

1. JWTs are signed using Ed25519-based EdDSA.
2. Protected endpoints validate JWT signatures and claims.
3. Token revocation is checked during authentication.
4. Risk-based policies determine whether MFA is required.
5. MFA challenges are stored persistently.
6. Email OTP delivery uses Gmail SMTP with STARTTLS.
7. Identity ledger integrity is checked using SHA-256 hash chaining.

## Testing

Run automated tests:

```bash
python -m pytest -v
```

Latest recorded automated test result:

- Total tests: 22
- Passed: 22
- Failed: 0

---

**Project:** Decentralized Zero-Trust Identity Provider Mesh

**Author:** Nama Jeevan Kumar
