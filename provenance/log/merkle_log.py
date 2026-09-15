"""
Tamper-evident provenance log: a SHA-256 Merkle tree (pymerkle) whose leaves are the canonical
signing-bytes of ProvenanceRecords. Signed with ML-DSA (NOT the conventional Ed25519) — the
substitution that, with the machine-checked attribution proof, is the project's unoccupied cell.

Implements the two protocol mechanisms the Tamarin model relies on:
  * append-only inclusion (Merkle proofs) -> tamper-evidence;
  * nonce dedup (UniqueCommitPerNonce) -> replay-injectivity of P3.
"""
from __future__ import annotations
from dataclasses import dataclass

from pymerkle import InmemoryTree, verify_inclusion, InvalidProof

from provenance.gateway.record import ProvenanceRecord


@dataclass
class LogEntry:
    index: int
    record: ProvenanceRecord
    signature_hex: str


class DuplicateNonce(Exception):
    pass


class ProvenanceLog:
    def __init__(self, algorithm: str = "sha256"):
        self._tree = InmemoryTree(algorithm=algorithm)
        self._entries: list[LogEntry] = []
        self._seen_nonces: set[str] = set()

    def commit(self, record: ProvenanceRecord, signature: bytes) -> LogEntry:
        """Append a signed record. Rejects a duplicate decision nonce (UniqueCommitPerNonce)."""
        if record.nonce in self._seen_nonces:
            raise DuplicateNonce(f"nonce already committed: {record.nonce}")
        index = self._tree.append_entry(record.signing_bytes())
        self._seen_nonces.add(record.nonce)
        entry = LogEntry(index=index, record=record, signature_hex=signature.hex())
        self._entries.append(entry)
        return entry

    def root(self) -> bytes:
        return self._tree.get_state()

    def prove_and_verify_inclusion(self, entry: LogEntry) -> bool:
        """Tamper-evidence check: the entry's record is provably in the log at the current root."""
        proof = self._tree.prove_inclusion(entry.index)
        leaf = self._tree.hash_buff(entry.record.signing_bytes())
        try:
            verify_inclusion(leaf, self.root(), proof)
            return True
        except InvalidProof:
            return False

    def __len__(self) -> int:
        return len(self._entries)
