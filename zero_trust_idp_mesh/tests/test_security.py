
import jwt

from app.security import (
    create_did_identity,
    issue_access_token,
    VERIFY_KEY,
)

print("Testing security.py...")

# Test identity creation
identity = create_did_identity("test_user")

assert identity["did"].startswith("did:key:z")
assert identity["document"]["id"] == identity["did"]

print("PASS: DID identity created")

# Test JWT creation
token = issue_access_token(
    "test_user",
    identity["did"],
    ["openid", "profile"],
    {"score": 0, "decision": "allow", "reasons": []},
)

assert isinstance(token, str) and len(token) > 0

print("PASS: JWT token generated")

# Test token signature and claims
claims = jwt.decode(
    token,
    VERIFY_KEY,
    algorithms=["EdDSA"],
    audience="idp-mesh-api",
    issuer="http://localhost:8000",
)

assert claims["sub"] == "test_user"
assert claims["did"] == identity["did"]

print("PASS: JWT signature verified")
print("ALL TESTS PASSED!")
