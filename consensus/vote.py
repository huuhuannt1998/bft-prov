"""
ML-DSA-signed BFT vote. Each vote binds the FULL context <pk_i, actuation, view, decision> into the
signed payload — the per-agent lift of the Phase-1 BUFF pk-binding rule (seed from
attribution_buff_fixed.spthy), which Task 4 relies on to close certificate-level mix-and-match and
cross-view replay.
"""
from __future__ import annotations
import json
from dataclasses import dataclass

from provenance.crypto.mldsa import MLDSAIdentity, verify, DOMAIN

VOTE_DOMAIN = DOMAIN.decode() + "|bft-vote/v1"


def _signing_bytes(agent_pk_hex: str, actuation: str, view: int, decision: str) -> bytes:
    return json.dumps({
        "d": VOTE_DOMAIN,
        "pk": agent_pk_hex,        # agent public key bound in (exclusive ownership at the vote level)
        "a": actuation,            # the actuation under vote
        "v": view,                 # consensus view/round (anti cross-view replay)
        "decision": decision,      # "approve" | "reject"
    }, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Vote:
    agent_id: str
    agent_pk_hex: str
    mldsa_alg: str
    actuation: str
    view: int
    decision: str
    signature_hex: str
    family: str = "unknown"   # model lineage (for correlation-aware quorum sizing, Task 6 follow-up)

    def signing_bytes(self) -> bytes:
        return _signing_bytes(self.agent_pk_hex, self.actuation, self.view, self.decision)

    def verify(self) -> bool:
        """The vote's ML-DSA signature verifies under the public key bound inside it."""
        return verify(self.mldsa_alg, self.signing_bytes(),
                      bytes.fromhex(self.signature_hex), bytes.fromhex(self.agent_pk_hex))


def cast_vote(agent_id: str, identity: MLDSAIdentity, actuation: str, view: int, decision: str,
              family: str = "unknown") -> Vote:
    pk_hex = identity.public_key.hex()
    sig = identity.sign(_signing_bytes(pk_hex, actuation, view, decision))
    return Vote(agent_id=agent_id, agent_pk_hex=pk_hex, mldsa_alg=identity.alg,
                actuation=actuation, view=view, decision=decision, signature_hex=sig.hex(),
                family=family)
