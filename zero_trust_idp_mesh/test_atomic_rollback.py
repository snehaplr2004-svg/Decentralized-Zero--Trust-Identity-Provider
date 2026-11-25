
import sqlite3

from app.identity_store import identity_registry, DB_PATH

test_subject = "atomic_rollback_test_01"

test_identity = {
    "did": "did:key:rollback-test-001",
    "document": {
        "id": "did:key:rollback-test-001",
        "test": True
    }
}

# Create a temporary trigger that forces ledger insertion to fail.
conn = sqlite3.connect(DB_PATH)

conn.execute("""
    CREATE TRIGGER simulate_ledger_failure
    BEFORE INSERT ON ledger
    BEGIN
        SELECT RAISE(ABORT, 'Simulated ledger failure');
    END;
""")

conn.commit()
conn.close()

try:
    # Attempt to register identity and ledger entry.
    result = identity_registry.register_identity_with_ledger(
        test_subject,
        test_identity
    )

    print("Registration result:", result)

finally:
    # Always remove the temporary trigger.
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TRIGGER IF EXISTS simulate_ledger_failure")
    conn.commit()
    conn.close()

# Check whether the identity was rolled back.
saved_identity = identity_registry.get_identity(test_subject)

print("Identity after failed registration:", saved_identity)

if result is None and saved_identity is None:
    print("SUCCESS: Atomic rollback verified!")
else:
    print("FAILED: Please investigate the transaction.")
