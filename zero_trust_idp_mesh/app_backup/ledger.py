
from datetime import datetime, timezone
import hashlib
import json


class IdentityLedger:
    def __init__(self):
        self.entries = []

    def anchor(self, did, document):
        previous_hash = (
            self.entries[-1]["hash"]
            if self.entries else "GENESIS"
        )

        entry = {
            "did": did,
            "document": document,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "previous_hash": previous_hash
        }

        encoded = json.dumps(
            entry, sort_keys=True
        ).encode()

        entry["hash"] = hashlib.sha256(
            encoded
        ).hexdigest()

        self.entries.append(entry)
        return entry

    def list_entries(self):
        return self.entries


ledger = IdentityLedger()
