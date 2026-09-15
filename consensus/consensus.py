"""
Signature-based BFT consensus round (PBFT/HotStuff normal-case path) for a single actuation decision.

Flow: leader proposes (actuation, view) -> replicas cast ML-DSA-signed votes -> collect 2f+1 distinct
authentic approve-votes -> form a quorum certificate (QC) -> WellFormedQC check -> the QC feeds the
Phase-1 provenance chain + OPA gate -> emulated actuation. The QC is the single artifact that both
witnesses BFT agreement and carries the post-quantum attribution.

Safety intuition (Apalache discharges it formally in Task 3): a certificate needs 2f+1 votes; with
<= f Byzantine agents, at least f+1 honest votes are required, so an actuation the honest majority
rejects cannot be certified. View changes / liveness (partial synchrony) are out of this normal-case
core and noted in the spec.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from provenance.crypto.mldsa import MLDSAIdentity
from consensus.vote import Vote
from consensus.replica import Replica
from consensus.certificate import QuorumCertificate, well_formed, quorum_size


@dataclass
class RoundResult:
    actuation: str
    view: int
    approve_count: int
    quorum_size: int
    certified: bool
    reason: str
    qc: QuorumCertificate | None = None


@dataclass
class Quorum:
    n: int
    f: int
    replicas: list[Replica] = field(default_factory=list)

    @property
    def authentic_pks(self) -> set[str]:
        return {r.identity.public_key.hex() for r in self.replicas}

    def run_round(self, actuation_id: str, device: str, command: str, view: int,
                  context: str = "", ingested: str = "") -> RoundResult:
        # Collect votes; each honest vote is the agent's model judgment on the proposal-plus-context.
        votes: list[Vote] = []
        for r in self.replicas:
            v = r.vote(actuation_id, device, command, view, context=context, ingested=ingested)
            if v is None:
                continue
            votes.extend(v if isinstance(v, list) else [v])

        # Tally distinct-agent approve votes (equivocation collapses to one agent via distinctness).
        approve = [v for v in votes if v.decision == "approve" and v.verify()
                   and v.actuation == actuation_id and v.view == view]
        qc = QuorumCertificate(actuation=actuation_id, view=view, votes=approve)
        ok, reason = well_formed(qc, self.n, self.f, self.authentic_pks)
        q = quorum_size(self.n, self.f)
        return RoundResult(actuation=actuation_id, view=view,
                           approve_count=len(qc.agent_pks), quorum_size=q,
                           certified=ok, reason=reason, qc=qc if ok else None)


def build_quorum(n: int, f: int, byzantine: dict[int, str] | None = None,
                 alg: str = "ML-DSA-65",
                 families: list[str] | None = None,
                 judges: dict[int, "JudgeFn"] | None = None,
                 default_judge: "JudgeFn | None" = None) -> Quorum:
    """Construct N replicas. `byzantine` maps index -> byz_mode (<= f). `families` tags each replica's
    model lineage; `judges`/`default_judge` supply the honest model-judgment voter (StubJudge in tests,
    OllamaJudge in real runs)."""
    from consensus.model_vote import JudgeFn  # noqa: F401 (type only)
    byzantine = byzantine or {}
    judges = judges or {}
    assert len(byzantine) <= f, "more Byzantine replicas than f"
    replicas = []
    for i in range(n):
        ident = MLDSAIdentity(alg)
        fam = families[i] if families and i < len(families) else f"fam-{i}"
        if i in byzantine:
            replicas.append(Replica(f"agent-{i}", ident, family=fam, byzantine=True, byz_mode=byzantine[i]))
        else:
            replicas.append(Replica(f"agent-{i}", ident, family=fam,
                                    judge=judges.get(i, default_judge)))
    return Quorum(n=n, f=f, replicas=replicas)


if __name__ == "__main__":
    # Mechanism demo with a deterministic StubJudge (no model calls): honest agents approve only the
    # safe action. Real model-judgment runs live in testbed/ and decorrelation/.
    from consensus.model_vote import StubJudge
    SAFE = {("light.kitchen", "turn_on")}
    honest = StubJudge(approve_set=SAFE)
    fams = ["llama", "qwen", "mistral", "gemma"]
    print("=== N=4, f=1 BFT actuation consensus (model-judgment votes; StubJudge) ===\n")

    # A: safe, all honest -> all approve -> certified.
    q = build_quorum(4, 1, families=fams, default_judge=honest)
    r = q.run_round("light.kitchen|turn_on|n1", "light.kitchen", "turn_on", view=1)
    print(f"A safe, all honest      : approve={r.approve_count}/{r.quorum_size} certified={r.certified} ({r.reason})")

    # B: UNSAFE (unlock), all honest deny; 1 Byzantine rubber-stamp approves -> 1 < quorum -> blocked.
    q = build_quorum(4, 1, byzantine={3: "approve_all"}, families=fams, default_judge=honest)
    r = q.run_round("front_door|unlock|n2", "input_boolean.front_door", "turn_on", view=2)
    print(f"B unsafe, 1 rubber-stamp: approve={r.approve_count}/{r.quorum_size} certified={r.certified} ({r.reason})")

    # C: safe, 1 equivocator -> equivocation absorbed by distinctness -> certified.
    q = build_quorum(4, 1, byzantine={2: "equivocate"}, families=fams, default_judge=honest)
    r = q.run_round("light.kitchen|turn_on|n3", "light.kitchen", "turn_on", view=3)
    print(f"C safe, 1 equivocator   : approve={r.approve_count}/{r.quorum_size} certified={r.certified} ({r.reason})")
