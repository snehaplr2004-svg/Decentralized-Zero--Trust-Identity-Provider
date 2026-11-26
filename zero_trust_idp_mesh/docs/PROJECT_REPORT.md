# Project Report
## Decentralized Zero-Trust Identity Provider Mesh

**Project Title:** Decentralized Zero-Trust Identity Provider Mesh

**Author:** Nama Jeevan Kumar

**Register Number:** 23BTCE247

**Technology:** Python, FastAPI, SQLite, JWT, Ed25519, Gmail SMTP

**Project Type:** Academic Internship Project

---

## Abstract

The Decentralized Zero-Trust Identity Provider Mesh is an identity and access-management prototype designed to demonstrate secure authentication and authorization using Zero-Trust security principles.

Traditional authentication systems often rely heavily on initial login verification. This project introduces additional security checks through risk-based access control, multi-factor authentication, cryptographically signed JSON Web Tokens, token revocation, and a tamper-evident identity ledger.

The application is developed using Python and FastAPI. It uses Decentralized Identifiers (DIDs), Ed25519 cryptography, SQLite databases, and Gmail SMTP for email-based OTP verification.

The main objective is to demonstrate how identity verification and access decisions can be strengthened through continuous validation and additional authentication when suspicious access conditions are detected.

---

## 1. Introduction

Identity management is an important part of modern application security. Systems must ensure that users are properly authenticated and that unauthorized access is prevented.

The Zero-Trust security model follows the principle of never automatically trusting a user or device. Every access request should be verified based on available identity and risk information.

This project implements a prototype identity provider that combines decentralized identity concepts with risk-based authentication and secure token management.

---

## 2. Problem Statement

Traditional authentication mechanisms may not sufficiently consider device security, access location, unusual access times, or the possibility that an issued access token has been compromised.

There is a need for an authentication system that:

- Verifies registered identities.
- Evaluates access requests using risk factors.
- Requires additional verification when necessary.
- Supports token revocation.
- Maintains verifiable identity registration records.

This project addresses these requirements through a Zero-Trust identity provider prototype.

---

## 3. Objectives

1. Develop a REST API using FastAPI.
2. Generate Decentralized Identifiers for registered identities.
3. Implement Ed25519-based JWT authentication.
4. Introduce risk-based access control.
5. Implement email-based multi-factor authentication.
6. Support secure token revocation through logout.
7. Maintain a SHA-256 hash-chain identity ledger.
8. Provide API endpoints for identity and ledger management.
9. Test the system using automated and manual API workflows.

---

## 4. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| FastAPI | REST API framework |
| Uvicorn | Application server |
| SQLite | Persistent data storage |
| PyJWT | JWT creation and validation |
| Ed25519 | Digital signature cryptography |
| SHA-256 | Hashing and ledger integrity |
| Pydantic | Request validation |
| Gmail SMTP | Email OTP delivery |
| pytest | Automated testing |
| python-dotenv | Environment configuration |

---

## 5. System Architecture

The system contains the following major components:

1. **Identity Management:** Creates and registers decentralized identities.
2. **Authentication Service:** Issues and validates signed JWT access tokens.
3. **Risk Evaluation Engine:** Evaluates IP address, device posture, and access time.
4. **MFA Service:** Generates, stores, and verifies OTP challenges.
5. **Email Service:** Delivers OTP codes through Gmail SMTP.
6. **Token Revocation Service:** Maintains revoked token records.
7. **Identity Ledger:** Maintains SHA-256 hash-linked identity records.
8. **REST API:** Provides endpoints for interaction with the system.

### Authentication Workflow

1. A user registers an identity.
2. The system generates a DID and identity document.
3. Identity information is stored and recorded in the ledger.
4. The user requests an access token.
5. The risk engine evaluates the access request.
6. If access is allowed, a JWT is issued.
7. If additional verification is required, an OTP is sent to the registered email address.
8. The user submits the OTP.
9. After successful verification, an access token is issued.
10. The token is used to access protected resources.
11. The user can log out to revoke the token.

---

## 6. Implementation

### 6.1 Identity Registration

The application generates a decentralized identifier using Ed25519 public-key information.

The identity registry stores the subject, DID, identity document, and optional email address.

Identity registration and ledger anchoring are performed together using the persistent storage implementation.

### 6.2 JWT Authentication

The application uses EdDSA with Ed25519 to sign access tokens.

Token validation checks the signature, issuer, audience, and expiration.

Invalid or expired tokens are rejected.

### 6.3 Risk-Based Access Control

The risk evaluation engine considers:

- IP address.
- Device posture.
- Access time.

It produces one of three decisions:

- Allow
- Step-up authentication
- Deny

### 6.4 Multi-Factor Authentication

When additional verification is required, the MFA service creates a six-digit OTP challenge.

The challenge includes:

- Five-minute expiration.
- Maximum five verification attempts.
- SHA-256 OTP hash storage.
- One-time verification.

### 6.5 Email Integration

Gmail SMTP is used to send OTP verification codes.

SMTP configuration is loaded from the local `.env` file. The email service uses STARTTLS and certificate validation.

In email-delivery mode, the OTP is not returned in the API response.

### 6.6 Token Revocation

The logout endpoint revokes the authenticated JWT using its unique token identifier.

Subsequent protected-resource requests reject the revoked token.

### 6.7 Identity Ledger

The ledger stores identity registration records using SHA-256 hash chaining.

Each entry references the previous entry's hash. A verification endpoint checks the integrity of the chain.

---

## 7. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Application health check |
| POST | `/identities` | Register identity |
| POST | `/token` | Request access token |
| POST | `/mfa/verify` | Verify OTP |
| GET | `/protected` | Access protected resource |
| POST | `/logout` | Revoke access token |
| GET | `/ledger` | Retrieve ledger entries |
| GET | `/ledger/verify` | Verify ledger integrity |
| GET | `/ledger/search` | Search ledger by DID |
| GET | `/ledger/{entry_id}` | Retrieve a ledger entry |

Interactive API documentation is available at:

`http://127.0.0.1:8000/docs`

---

## 8. Testing and Results

The project was tested using pytest and manual API testing through FastAPI Swagger documentation.

### Automated Testing

The latest recorded automated test run produced:

- Total tests: 22
- Passed: 22
- Failed: 0

### Manual Testing

The following workflows were tested:

1. Application health check.
2. Identity registration.
3. Access token generation.
4. Risk-based MFA challenge.
5. Email OTP delivery.
6. OTP verification and token issuance.
7. Protected endpoint access.
8. Logout and token revocation.
9. Ledger integrity verification.

### Observed Results

- Email OTP was successfully received and verified.
- The authenticated token successfully accessed the protected endpoint.
- After logout, the same token was rejected with HTTP 401.
- Ledger verification reported a valid hash chain for all 14 entries checked during the recorded test.

These results represent development testing of the academic prototype.

---

## 9. Security Features

The project demonstrates:

- Decentralized identity generation.
- Ed25519-based digital signatures.
- JWT issuer and audience validation.
- Risk-based access decisions.
- Email-based multi-factor authentication.
- OTP expiration and attempt limits.
- Persistent token revocation.
- SHA-256 hash-chain integrity verification.
- Local environment-based secret configuration.

---

## 10. Limitations and Future Enhancements

The current implementation is an academic prototype and requires additional work before production deployment.

Potential improvements include:

1. Email ownership verification.
2. Login and OTP rate limiting.
3. HTTPS deployment.
4. Advanced private-key management.
5. Improved monitoring and audit logging.
6. Database backup and recovery.
7. Independent security testing.
8. Multi-node identity synchronization.
9. Distributed consensus and ledger integration.

The current SQLite hash-chain ledger is tamper-evident but is not a fully distributed blockchain network.

---

## 11. Conclusion

The Decentralized Zero-Trust Identity Provider Mesh demonstrates how modern identity and authentication technologies can be combined to improve access security.

The project integrates decentralized identifiers, Ed25519-based JWT authentication, risk-based access control, email-based MFA, token revocation, and a SHA-256 hash-chain ledger.

The implementation was evaluated through automated tests and manual API workflows. The results demonstrate the successful operation of the implemented academic prototype.

Further development and security hardening can improve its reliability, scalability, and suitability for real-world deployment.

---

**End of Project Report**

**Author:** Nama Jeevan Kumar

**Register Number:** 23BTCE247
