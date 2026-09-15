"""
Decision -> actuation provenance record (the hop the Tamarin model commits and the actuation
terminates at). Canonical, deterministic serialization so the signature and the Merkle-log leaf
are reproducible.

Task-3 design rule (machine-checked in attribution_buff_fixed.spthy): bind the asserter's PUBLIC
KEY and a domain/context tag INTO the signed payload, and dedup by the decision nonce. The verifier
credits a record only if the credited key equals the key bound in the record.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, asdict, field

from provenance.crypto.mldsa import DOMAIN


def new_nonce() -> str:
    return os.urandom(16).hex()


@dataclass(frozen=True)
class ActuationIntent:
    """What the (untrusted) agent proposes."""
    device: str          # e.g. "input_boolean.front_door"
    command: str         # e.g. "turn_on" / "turn_off" / "toggle"
    context_hash: str    # hash binding the decision to its triggering context
    nonce: str = field(default_factory=new_nonce)


@dataclass(frozen=True)
class ProvenanceRecord:
    """The signed, logged decision->actuation record. `agent_pk_hex` is the BOUND public key."""
    domain: str
    agent_id: str
    agent_pk_hex: str
    mldsa_alg: str
    device: str
    command: str
    context_hash: str
    nonce: str
    policy_decision: str   # "permit" | "deny" — set by the guard

    def signing_bytes(self) -> bytes:
        """Canonical bytes that get ML-DSA-signed. pk + domain are bound in (the BUFF binding)."""
        payload = {
            "domain": self.domain,
            "agent_id": self.agent_id,
            "agent_pk_hex": self.agent_pk_hex,
            "mldsa_alg": self.mldsa_alg,
            "device": self.device,
            "command": self.command,
            "context_hash": self.context_hash,
            "nonce": self.nonce,
            "policy_decision": self.policy_decision,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def build_record(agent_id: str, agent_pk: bytes, alg: str,
                 intent: ActuationIntent, policy_decision: str) -> ProvenanceRecord:
    return ProvenanceRecord(
        domain=DOMAIN.decode(),
        agent_id=agent_id,
        agent_pk_hex=agent_pk.hex(),
        mldsa_alg=alg,
        device=intent.device,
        command=intent.command,
        context_hash=intent.context_hash,
        nonce=intent.nonce,
        policy_decision=policy_decision,
    )
