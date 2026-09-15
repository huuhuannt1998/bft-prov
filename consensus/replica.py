"""
A consensus replica = one LLM-agent's signing identity + its model-judgment voter (Phase 3a).

Per the ratified vote semantics (dec_01KVXH1K1S2KSV2WB05K933T19): an honest replica's vote IS its
model's judgment on the proposal-plus-context (the LLM decides, not OPA). Injection-resistance lives in
model diversity in the vote path. The OPA categorical floor is applied POST-quorum (consensus/integration),
not here. Byzantine replicas (<= f) vote adversarially; the `approve_all` rubber-stamp is retained ONLY
as a clearly-labeled worst-case adjunct, kept strictly separate from real-injection results.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from provenance.crypto.mldsa import MLDSAIdentity
from consensus.vote import Vote, cast_vote
from consensus.model_vote import JudgeFn


@dataclass
class Replica:
    agent_id: str
    identity: MLDSAIdentity
    family: str = "unknown"           # model lineage (for correlation-aware quorum + decorrelation)
    judge: JudgeFn | None = None      # the agent's model judgment = its vote (honest path)
    byzantine: bool = False
    byz_mode: str = "approve_all"     # "approve_all" (rubber-stamp adjunct) | "equivocate" | "silent"

    def vote(self, actuation_id: str, device: str, command: str, view: int,
             context: str = "", ingested: str = "") -> Vote | list[Vote] | None:
        if self.byzantine:
            if self.byz_mode == "silent":
                return None
            if self.byz_mode == "approve_all":
                # Worst-case Byzantine (always approve). Labeled adjunct, NOT a real injection.
                return cast_vote(self.agent_id, self.identity, actuation_id, view, "approve", self.family)
            if self.byz_mode == "equivocate":
                return [cast_vote(self.agent_id, self.identity, actuation_id, view, "approve", self.family),
                        cast_vote(self.agent_id, self.identity, actuation_id, view, "reject", self.family)]
        # Honest path: the agent's MODEL judges the proposal in context; that judgment is the vote.
        if self.judge is None:
            raise ValueError(f"honest replica {self.agent_id} has no model judge configured")
        approve = self.judge(device, command, context, ingested)
        decision = "approve" if approve else "reject"
        return cast_vote(self.agent_id, self.identity, actuation_id, view, decision, self.family)
