"""
Post-quantum quorum certificate (QC) — the PQC<->BFT fusion artifact.

A QC is an AGGREGATE (concatenation) of 2f+1 distinct, valid, ML-DSA-signed approve-votes for the
SAME (actuation, view). It is simultaneously the BFT-safety witness (2f+1 agreement) and the
attribution token (2f+1 ML-DSA signatures). `well_formed` is the shared `WellFormedQC` interface from
the Task-1 joint-property spec — Tamarin reads `ValidVote` cryptographically (here), Apalache reads it
abstractly (Task 3); Task 5 shows the two readings coincide.

Threshold ML-DSA (a single compact certificate) is a STRETCH goal; Phase 2 uses the aggregate.
"""
from __future__ import annotations
from dataclasses import dataclass

from consensus.vote import Vote


def quorum_size(n: int, f: int) -> int:
    return 2 * f + 1


@dataclass
class QuorumCertificate:
    actuation: str
    view: int
    votes: list[Vote]

    @property
    def agent_pks(self) -> set[str]:
        return {v.agent_pk_hex for v in self.votes}


def well_formed(qc: QuorumCertificate, n: int, f: int,
                authentic_pks: set[str]) -> tuple[bool, str]:
    """WellFormedQC(a, v, Q): |Q| = 2f+1 distinct authentic agents, all approve-votes for the SAME
    (a, v), every ML-DSA signature valid. Returns (ok, reason)."""
    q = quorum_size(n, f)
    seen: set[str] = set()
    approve = [v for v in qc.votes if v.decision == "approve"]
    for v in approve:
        # (i) cryptographic validity — exclusive-ownership-bound vote
        if not v.verify():
            return False, f"invalid signature from {v.agent_id}"
        # (ii) same (actuation, view) — blocks mix-and-match / cross-view replay
        if v.actuation != qc.actuation or v.view != qc.view:
            return False, f"vote context mismatch from {v.agent_id}"
        # (iii) authentic registered agent
        if v.agent_pk_hex not in authentic_pks:
            return False, f"unregistered key from {v.agent_id}"
        # (iv) distinct agents — blocks ballot stuffing / agent-set substitution
        if v.agent_pk_hex in seen:
            return False, f"duplicate agent {v.agent_id}"
        seen.add(v.agent_pk_hex)
    if len(seen) < q:
        return False, f"insufficient quorum: {len(seen)} < {q}"
    return True, "well-formed"


def well_formed_diverse(qc: QuorumCertificate, n: int, f: int, authentic_pks: set[str],
                        pk_family: dict[str, str], min_families: int,
                        cap_per_family: int | None = None) -> tuple[bool, str]:
    """Correlation-aware WellFormedQC (Task-6 follow-up). All of `well_formed`, PLUS the quorum must
    span >= `min_families` distinct AUTHENTIC families (looked up from the registry `pk_family`, never
    self-reported), and no single family may contribute more than `cap_per_family` votes (default:
    less than a majority of the quorum). This blocks a single correlated cluster (one family flipped
    together by an injection) from carrying the quorum alone — for clusters smaller than min_families.
    Sizing it to beat an injection requires min_families > that injection's cross-family flip count."""
    ok, reason = well_formed(qc, n, f, authentic_pks)
    if not ok:
        return False, reason
    q = quorum_size(n, f)
    cap = cap_per_family if cap_per_family is not None else (q // 2)  # strictly less than majority
    approve = [v for v in qc.votes if v.decision == "approve"]
    fams: dict[str, int] = {}
    for v in approve:
        fam = pk_family.get(v.agent_pk_hex, "unknown")
        fams[fam] = fams.get(fam, 0) + 1
    if any(cnt > cap for cnt in fams.values()):
        worst = max(fams, key=fams.get)
        return False, f"family '{worst}' exceeds cap ({fams[worst]} > {cap}) — correlated cluster"
    if len(fams) < min_families:
        return False, f"insufficient family diversity: {len(fams)} < {min_families}"
    return True, f"well-formed (diverse: {len(fams)} families)"
