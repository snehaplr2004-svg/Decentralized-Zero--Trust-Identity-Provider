"""
Simulated blockchain ledger.

Every DID Document registration appends a new block. Blocks are chained
by SHA-256 of (index, timestamp, document, prev_hash). The chain is
verifiable via `.verify()`.

This is intentionally simple — swap for a real ledger (Hyperledger,
IPFS, or a testnet) in production.
"""
import hashlib
import json
import time
from dataclasses import dataclass, field


@dataclass
class Block:
    index: int
    timestamp: float
    did_document: dict
    prev_hash: str
    hash: str = field(default="")

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "did_document": self.did_document,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "did_document": self.did_document,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class SimulatedLedger:
    def __init__(self) -> None:
        self.chain: list[Block] = [self._genesis()]

    def _genesis(self) -> Block:
        b = Block(0, time.time(), {"genesis": True}, "0" * 64)
        b.hash = b.compute_hash()
        return b

    def anchor(self, did_document: dict) -> Block:
        prev = self.chain[-1]
        b = Block(len(self.chain), time.time(), did_document, prev.hash)
        b.hash = b.compute_hash()
        self.chain.append(b)
        return b

    def get_did(self, did: str) -> dict | None:
        for block in reversed(self.chain):
            if block.did_document.get("id") == did:
                return block.did_document
        return None

    def verify(self) -> bool:
        for i in range(1, len(self.chain)):
            cur, prev = self.chain[i], self.chain[i - 1]
            if cur.hash != cur.compute_hash() or cur.prev_hash != prev.hash:
                return False
        return True


# Module-level singleton
ledger = SimulatedLedger()