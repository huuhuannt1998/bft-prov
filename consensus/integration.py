"""
Bridge: a certified quorum certificate (QC) feeds the Phase-1 provenance chain + OPA gate before the
emulated actuation. The QC — not a single agent's signature — is now the attribution token committed
to the tamper-evident log. This is the Phase-1 -> Phase-2 lift of the provenance record.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass

from consensus.consensus import Quorum, RoundResult
from consensus.certificate import QuorumCertificate
from consensus.model_vote import categorical_deny
from provenance.log.merkle_log import ProvenanceLog, DuplicateNonce
from actuation.homeassistant.virtual_device import HAVirtualDevice


def qc_digest(qc: QuorumCertificate) -> str:
    """Canonical digest of the certificate (the 2f+1 votes), used as the log leaf / attribution id."""
    body = json.dumps({
        "actuation": qc.actuation, "view": qc.view,
        "votes": sorted(v.signing_bytes().decode() + "|" + v.signature_hex for v in qc.votes
                        if v.decision == "approve"),
    }, sort_keys=True).encode()
    return hashlib.sha256(body).hexdigest()


@dataclass
class ActuationOutcome:
    actuation: str
    certified: bool
    committed: bool
    actuated: bool
    reason: str
    qc_digest: str | None = None
    transition: dict | None = None


class QuorumActuationPipeline:
    def __init__(self, quorum: Quorum, log: ProvenanceLog | None = None,
                 device: HAVirtualDevice | None = None):
        self.quorum = quorum
        self.log = log or ProvenanceLog()
        self.device = device or HAVirtualDevice()
        self._committed_digests: set[str] = set()

    def decide_and_actuate(self, actuation_id: str, device: str, command: str, view: int,
                           context: str = "", ingested: str = "") -> ActuationOutcome:
        r: RoundResult = self.quorum.run_round(actuation_id, device, command, view,
                                               context=context, ingested=ingested)
        if not r.certified:
            return ActuationOutcome(actuation_id, False, False, False, f"no certificate: {r.reason}")

        # ATTRIBUTION FLOOR: a quorum certified -> a valid certificate exists naming the 2f+1 keys,
        # REGARDLESS of whether the action is ultimately actuated. This holds even when an injection
        # has defeated the quorum on an unsafe action (the certificate then names exactly who approved it).
        digest = qc_digest(r.qc)
        if digest in self._committed_digests:
            return ActuationOutcome(actuation_id, True, False, False, "duplicate QC (replay)", digest)
        self._committed_digests.add(digest)

        # CATEGORICAL FLOOR (post-quorum hard-deny): the three human-authority absolutes are never
        # actuated, even on a unanimous (fully-injected) certificate. The certificate still exists.
        if categorical_deny(device, command):
            return ActuationOutcome(actuation_id, True, False, False,
                                    "categorical floor: blocked (attributed)", digest)

        transition = self.device.call_service(command)
        return ActuationOutcome(actuation_id, True, True, True, "actuated", digest, transition)


if __name__ == "__main__":
    from consensus.consensus import build_quorum
    from consensus.model_vote import StubJudge
    fams = ["llama", "qwen", "mistral", "gemma"]
    honest = StubJudge(approve_set={("light.kitchen", "turn_on")})

    # unsafe (unlock): honest models deny; 1 rubber-stamp approves -> 1 < quorum -> no cert, not actuated
    pipe = QuorumActuationPipeline(build_quorum(4, 1, byzantine={3: "approve_all"}, families=fams, default_judge=honest))
    o1 = pipe.decide_and_actuate("front_door|unlock|n1", "input_boolean.front_door", "turn_on", 1)
    print(f"unsafe (1 rubber-stamp): certified={o1.certified} actuated={o1.actuated} ({o1.reason})")

    # safe: all honest approve -> certified -> actuated, attributed by QC digest
    pipe = QuorumActuationPipeline(build_quorum(4, 1, families=fams, default_judge=honest))
    o2 = pipe.decide_and_actuate("light.kitchen|turn_on|n2", "light.kitchen", "turn_on", 2)
    print(f"safe                   : certified={o2.certified} actuated={o2.actuated} qc={o2.qc_digest[:16] if o2.qc_digest else None}")

    # categorical floor: even if all 4 approve, disabling the smoke alarm is hard-denied (but attributed)
    allapprove = StubJudge(flipped=True)
    pipe = QuorumActuationPipeline(build_quorum(4, 1, families=fams, default_judge=allapprove))
    o3 = pipe.decide_and_actuate("alarm.smoke|off|n3", "alarm.smoke_detector", "turn_off", 3)
    print(f"floor (smoke off, all approve): certified={o3.certified} actuated={o3.actuated} attributed_qc={o3.qc_digest[:16] if o3.qc_digest else None} ({o3.reason})")
