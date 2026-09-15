"""Authorization certificate v1: explicit wire schema, enrollment registry, coverage predicate,
and a real replay/epoch state machine.

This replaces the thin `QuorumCertificate` for measurement and verification purposes. Three things
here are load-bearing for the paper's claims and were previously only described:

* PUBLIC KEYS ARE NOT CARRIED IN THE CERTIFICATE.  A vote references its signer by `key_id`; the
  public key, declared configuration, and revocation state live in an enrollment `Registry`. Storage
  accounting must therefore separate per-certificate bytes from one-off registry bytes.

* REPLAY IS ENFORCED, NOT ASSUMED.  `CommitStore` is a compare-and-set over (certificate id, nonce,
  (device, sequence)) with a durable committed set; a second commit of the same certificate fails.
  The symbolic model's uniqueness restriction is the abstraction of this store, not a substitute.

* COVERAGE IS A PREDICATE OVER DECLARED DOMAINS FROM THE REGISTRY, never self-reported by the signer.
  A vote that claims a family the registry does not record for its key is rejected.

Canonical encoding is JSON with sorted keys and no whitespace, so certificate bytes are reproducible.
A compact binary encoding would reduce framing overhead; we report the JSON figure we actually run.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

from provenance.crypto.mldsa import MLDSAIdentity, verify as mldsa_verify

CERT_VERSION = "authz-cert/v1"
VOTE_DOMAIN = "PQ-BFT-Prov/smart-home-actuation/v1|authz-vote/v1"


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- enrollment registry

@dataclass
class Enrollment:
    """What the operator registered for one signing key. The signer never asserts these itself."""
    key_id: str
    public_key_hex: str
    alg: str
    model_id: str
    model_weight_hash: str
    quantization: str
    runtime: str
    defense_id: str
    family: str
    key_domain: str            # process / container / host / secure element the key lives in
    enrolled_epoch: int
    revoked_epoch: int | None = None   # revoked at the START of this epoch

    def active_at(self, epoch: int) -> bool:
        return self.enrolled_epoch <= epoch and (self.revoked_epoch is None or epoch < self.revoked_epoch)

    def domains(self) -> dict[str, str]:
        return {"family": self.family, "defense": self.defense_id, "quantization": self.quantization,
                "runtime": self.runtime, "key_domain": self.key_domain}


class Registry:
    def __init__(self) -> None:
        self._by_id: dict[str, Enrollment] = {}

    def enroll(self, e: Enrollment) -> None:
        if e.key_id in self._by_id:
            raise ValueError(f"duplicate key_id {e.key_id}")
        self._by_id[e.key_id] = e

    def get(self, key_id: str) -> Enrollment | None:
        return self._by_id.get(key_id)

    def revoke(self, key_id: str, epoch: int) -> None:
        self._by_id[key_id].revoked_epoch = epoch

    def bytes_size(self) -> int:
        return len(canon([asdict(e) for e in self._by_id.values()]))


# ---------------------------------------------------------------- vote and certificate

@dataclass(frozen=True)
class ActionRecord:
    """The common, signer-independent part every vote in a certificate must bind identically."""
    action_id: str
    device_id: str
    action: str
    args: dict
    risk_tier: str
    request_commitment: str        # h(trusted user request)
    context_commitment: str        # h(untrusted ingested context)
    system_prompt_commitment: str
    policy_commitment: str         # h(deterministic-verifier policy bundle)
    epoch: int
    view: int
    nonce: str
    sequence: int
    timestamp: str
    prev_checkpoint: str

    def commitment(self) -> str:
        return h(canon(asdict(self)))


@dataclass(frozen=True)
class SignedVote:
    key_id: str
    decision: str                  # "approve" | "deny"
    action_commitment: str         # binds the whole ActionRecord
    signature_hex: str

    def signing_bytes(self) -> bytes:
        return canon({"d": VOTE_DOMAIN, "kid": self.key_id,
                      "ac": self.action_commitment, "decision": self.decision})


def cast_vote(key_id: str, identity: MLDSAIdentity, action: ActionRecord, decision: str) -> SignedVote:
    v = SignedVote(key_id=key_id, decision=decision,
                   action_commitment=action.commitment(), signature_hex="")
    sig = identity.sign(v.signing_bytes())
    return SignedVote(key_id, decision, v.action_commitment, sig.hex())


@dataclass
class Certificate:
    version: str
    action: ActionRecord
    votes: list[SignedVote]
    quorum_policy_id: str
    gateway_decision: str = "pending"
    coverage_evidence: dict = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        return canon({"version": self.version, "action": asdict(self.action),
                      "votes": [asdict(v) for v in self.votes],
                      "quorum_policy_id": self.quorum_policy_id,
                      "gateway_decision": self.gateway_decision,
                      "coverage_evidence": self.coverage_evidence})

    @staticmethod
    def from_bytes(b: bytes) -> "Certificate":
        d = json.loads(b)
        return Certificate(version=d["version"], action=ActionRecord(**d["action"]),
                           votes=[SignedVote(**v) for v in d["votes"]],
                           quorum_policy_id=d["quorum_policy_id"],
                           gateway_decision=d["gateway_decision"],
                           coverage_evidence=d["coverage_evidence"])

    def leaf_hash(self) -> str:
        return h(self.to_bytes())


# ---------------------------------------------------------------- quorum policy

@dataclass(frozen=True)
class QuorumPolicy:
    policy_id: str
    q: int                                   # minimum distinct approving keys
    min_domains: dict[str, int] = field(default_factory=dict)   # e.g. {"family": 3, "defense": 2}
    max_per_domain: dict[str, int] = field(default_factory=dict)  # e.g. {"family": 2}


def check_certificate(cert: Certificate, reg: Registry, policy: QuorumPolicy,
                      now_epoch: int) -> tuple[bool, str]:
    """The verification predicate the formal model mirrors. Order matters only for the error
    reported; every clause is checked before a certificate is accepted."""
    if cert.version != CERT_VERSION:
        return False, "bad version"
    ac = cert.action.commitment()
    if cert.action.epoch != now_epoch:
        return False, "epoch mismatch"
    seen: set[str] = set()
    approving: list[Enrollment] = []
    for v in cert.votes:
        if v.decision != "approve":
            continue
        if v.action_commitment != ac:
            return False, f"vote does not bind this action record ({v.key_id})"
        e = reg.get(v.key_id)
        if e is None:
            return False, f"unregistered key {v.key_id}"
        if not e.active_at(cert.action.epoch):
            return False, f"key not active in epoch {cert.action.epoch} ({v.key_id})"
        if v.key_id in seen:
            return False, f"duplicate signer {v.key_id}"
        try:
            ok = mldsa_verify(e.alg, v.signing_bytes(), bytes.fromhex(v.signature_hex),
                              bytes.fromhex(e.public_key_hex))
        except Exception:
            return False, f"malformed signature ({v.key_id})"
        if not ok:
            return False, f"invalid signature ({v.key_id})"
        seen.add(v.key_id)
        approving.append(e)
    if len(approving) < policy.q:
        return False, f"insufficient quorum: {len(approving)} < {policy.q}"
    for dom, need in policy.min_domains.items():
        got = {e.domains()[dom] for e in approving}
        if len(got) < need:
            return False, f"coverage: only {len(got)} distinct {dom} < {need}"
    for dom, cap in policy.max_per_domain.items():
        counts: dict[str, int] = {}
        for e in approving:
            k = e.domains()[dom]
            counts[k] = counts.get(k, 0) + 1
        if any(c > cap for c in counts.values()):
            worst = max(counts, key=counts.get)
            return False, f"coverage: {dom}='{worst}' contributes {counts[worst]} > {cap}"
    return True, "valid"


def coverage_evidence(cert: Certificate, reg: Registry) -> dict:
    """Registry-derived domain multiset for the approving keys (never signer-asserted)."""
    ev: dict[str, dict[str, int]] = {}
    for v in cert.votes:
        if v.decision != "approve":
            continue
        e = reg.get(v.key_id)
        if e is None:
            continue
        for dom, val in e.domains().items():
            ev.setdefault(dom, {})
            ev[dom][val] = ev[dom].get(val, 0) + 1
    return ev


# ---------------------------------------------------------------- replay / commit state

class ReplayRejected(Exception):
    pass


class CommitStore:
    """Compare-and-set commit state. This is the mechanism the symbolic model's uniqueness
    restriction abstracts: a certificate id, its nonce, and its (device, sequence) may each transition
    to committed at most once."""

    def __init__(self) -> None:
        self._committed: set[str] = set()
        self._nonces: set[str] = set()
        self._seq: dict[str, int] = {}

    def commit(self, cert: Certificate) -> str:
        cid = cert.leaf_hash()
        a = cert.action
        if cid in self._committed:
            raise ReplayRejected("certificate already committed")
        if a.nonce in self._nonces:
            raise ReplayRejected("nonce reuse")
        last = self._seq.get(a.device_id)
        if last is not None and a.sequence <= last:
            raise ReplayRejected(f"sequence {a.sequence} not greater than {last}")
        self._committed.add(cid)
        self._nonces.add(a.nonce)
        self._seq[a.device_id] = a.sequence
        return cid
