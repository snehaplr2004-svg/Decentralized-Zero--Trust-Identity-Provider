
import sqlite3
import tempfile
from pathlib import Path
from contextlib import closing

from app.ledger import IdentityLedger


with tempfile.TemporaryDirectory() as temp_dir:

    test_db = Path(temp_dir) / "tamper_test.db"

    # Create a separate test ledger
    test_ledger = IdentityLedger(test_db)

    # Add two test entries
    test_ledger.anchor(
        "did:key:test001",
        {"name": "Alice"}
    )

    test_ledger.anchor(
        "did:key:test002",
        {"name": "Bob"}
    )

    print("Original ledger verification:")
    print(test_ledger.verify_chain())

    # Simulate unauthorized modification
    with closing(sqlite3.connect(test_db)) as conn:
        with conn:
            conn.execute("""
                UPDATE ledger
                SET document = ?
                WHERE did = ?
            """, (
                '{"name": "Modified Alice"}',
                "did:key:test001"
            ))

    print("\nVerification after tampering:")

    result = test_ledger.verify_chain()
    print(result)

    if result["valid"] is False:
        print("\nSUCCESS: Ledger tampering detected!")
    else:
        print("\nFAILED: Ledger tampering was not detected!")
