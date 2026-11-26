# Decentralized Zero-Trust Identity Provider Mesh

A decentralized identity and authentication system built using Python and FastAPI, implementing Zero-Trust security principles, Decentralized Identifiers (DIDs), risk-based authentication, Multi-Factor Authentication (MFA), JWT security, token revocation, and a tamper-evident identity ledger.

## Project Overview

The project provides secure identity registration, authentication, and access management.

It follows the Zero-Trust principle:

**Never trust, always verify.**

Every authentication request is evaluated using identity information, device posture, and risk-based access policies. Suspicious access conditions trigger additional verification.

## Key Features

- Decentralized Identifier (DID) generation using `did:key`.
- Ed25519 cryptographic signing.
- JWT authentication using EdDSA.
- Persistent cryptographic signing keys.
- SQLite identity registry.
- Risk-based authentication.
- Six-digit Multi-Factor Authentication.
- Gmail SMTP integration for OTP delivery.
- Five-minute OTP expiration.
- Maximum five OTP verification attempts.
- One-time OTP verification.
- Persistent token revocation.
- Secure logout.
- Protected API endpoints.
- SHA-256 hash-chain identity ledger.
- Ledger integrity verification.
- Ledger search and pagination.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| FastAPI | REST API framework |
| Uvicorn | ASGI server |
| SQLite | Persistent storage |
| PyJWT | JWT authentication |
| Ed25519 | Digital signatures |
| Pydantic | Request validation |
| Gmail SMTP | Email OTP delivery |
| SHA-256 | Ledger integrity |
| Pytest | Automated testing |
| python-dotenv | Environment configuration |

## Project Structure

```text
zero_trust_idp_mesh/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── security.py
│   ├── identity_store.py
│   ├── ledger.py
│   ├── policy.py
│   ├── revocation.py
│   ├── mfa.py
│   └── email_service.py
├── tests/
│   ├── test_api.py
│   ├── test_logout.py
│   ├── test_mfa.py
│   ├── test_mfa_persistence.py
│   ├── test_persistent_key.py
│   ├── test_policy.py
│   ├── test_production_mfa.py
│   ├── test_revocation.py
│   └── test_security.py
├── docs/
├── keys/
├── .env
├── .gitignore
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the application directory

```bash
cd zero_trust_idp_mesh
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file in the project root.

Example:

```env
APP_ENV=development
EXPOSE_DEVELOPMENT_OTP=false

EMAIL_MFA_ENABLED=true

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_gmail_address
SMTP_PASSWORD=your_gmail_app_password
EMAIL_FROM=your_gmail_address
```

**Security notes:**

- Use a Gmail App Password, not your normal Gmail password.
- Keep `.env` private.
- Never commit SMTP credentials or private signing keys.
- Keep development OTP exposure disabled for production.

### 7. Start the application

```bash
python -m uvicorn app.main:app --reload
```

Application URL:

http://127.0.0.1:8000

Swagger documentation:

http://127.0.0.1:8000/docs

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Application health |
| POST | `/identities` | Register identity |
| POST | `/token` | Authenticate and request token |
| POST | `/mfa/verify` | Verify email OTP |
| POST | `/logout` | Revoke access token |
| GET | `/protected` | Access protected resource |
| GET | `/ledger` | Retrieve ledger entries |
| GET | `/ledger/verify` | Verify ledger integrity |
| GET | `/ledger/search` | Search ledger by DID |
| GET | `/ledger/{entry_id}` | Retrieve a ledger entry |

## Authentication Workflow

1. User registers an identity.
2. System generates a decentralized identifier.
3. Identity information is stored in SQLite.
4. A corresponding ledger entry is created.
5. User requests authentication.
6. Risk evaluation checks access conditions.
7. Low-risk requests receive an access token.
8. Suspicious requests trigger MFA.
9. A six-digit OTP is sent through Gmail SMTP.
10. User submits the OTP for verification.
11. A JWT is issued after successful verification.
12. The JWT grants access to protected resources.
13. Logout revokes the token.

## Risk-Based Access Control

The system evaluates:

- IP address.
- Device posture.
- Access time.

| Decision | Meaning |
|---|---|
| Allow | Grant access |
| Step-up | Require additional verification |
| Deny | Reject access |

## Security Features

### Decentralized Identity

Uses `did:key` identifiers with Ed25519 public-key cryptography.

### JWT Authentication

Uses EdDSA-signed JWTs for authentication and authorization.

### Multi-Factor Authentication

- Six-digit OTP.
- Five-minute expiry.
- Maximum five attempts.
- One-time verification.
- SHA-256 OTP hash storage.
- Email delivery through Gmail SMTP.

### Token Revocation

Revoked JWT identifiers are stored persistently in SQLite and checked when protected endpoints are accessed.

### Tamper-Evident Ledger

Each ledger entry contains a SHA-256 hash linked to the previous entry. Ledger verification checks the integrity of the stored chain.

## Database Storage

| File | Purpose |
|---|---|
| `zero_trust.db` | Identity registry, ledger and MFA challenges |
| `revocations.db` | Revoked JWT records |
| `keys/jwt_ed25519_private.pem` | Persistent private signing key |

Keep these files backed up securely. Do not delete them when updating the application.

## Running Tests

Run all automated tests:

```bash
python -m pytest -v
```

Compile the application:

```bash
python -m compileall -f app
```

### Latest Automated Test Results

- Total tests: 22
- Passed: 22
- Failed: 0

Manual testing also verified email MFA, protected-resource access, logout and token revocation, and ledger integrity.

## Future Enhancements

- Production-grade email verification and enrollment.
- Rate limiting and brute-force protection.
- HTTPS and secure deployment.
- Distributed identity-provider synchronization.
- Enhanced device posture verification.
- Centralized monitoring and audit logging.
- Hardware-backed signing-key protection.

## Project Status

Core identity registration, authentication, risk-based access control, MFA, token revocation, and ledger verification have been implemented and tested.

This is an academic project prototype. Additional hardening and independent security review are required before production deployment.

## Author

**Nama Jeevan Kumar**

Decentralized Zero-Trust Identity Provider Mesh
