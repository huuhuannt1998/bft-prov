"""
End-to-end PQ-BFT-Prov provenance-to-(emulated)-actuation pipeline (Task 5 demonstrator skeleton).

Flow (single honest agent, Phase 1):
  (untrusted) agent intent
    -> OPA/Rego guard          (P2: decision made OUTSIDE the agent)
    -> build record bound to agent pk + domain tag   (Task-3 BUFF binding)
    -> ML-DSA sign             (post-quantum provenance signature)
    -> Merkle log commit       (tamper-evident; nonce dedup = UniqueCommitPerNonce)
    -> verify                  (sig under credited pk + pk-binding + inclusion + policy==permit)
    -> actuate emulated HA virtual device   (logged command; NEVER physical)

The LLM is an UNTRUSTED ORACLE: `propose_intent` may call a local Ollama model, but its output is
only a *proposed* intent — the guard, not the model, decides whether anything actuates. A denied or
forged request never reaches the device.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass

from provenance.crypto.mldsa import MLDSAIdentity, verify, DOMAIN
from provenance.gateway.record import ActuationIntent, build_record, ProvenanceRecord
from provenance.log.merkle_log import ProvenanceLog, DuplicateNonce
from actuation.homeassistant.virtual_device import HAVirtualDevice
from agent.guard.guard import evaluate as guard_evaluate


@dataclass
class PipelineResult:
    intent: ActuationIntent
    policy_decision: str
    committed: bool
    verified: bool
    actuated: bool
    reason: str
    transition: dict | None = None


def context_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ProvenancePipeline:
    def __init__(self, agent_id: str, identity: MLDSAIdentity,
                 log: ProvenanceLog | None = None, device: HAVirtualDevice | None = None):
        self.agent_id = agent_id
        self.identity = identity
        self.log = log or ProvenanceLog()
        self.device = device or HAVirtualDevice()

    def run(self, intent: ActuationIntent, authorized: bool = False) -> PipelineResult:
        # 1. Guard decides (agent has no say).
        decision = guard_evaluate(intent.device, intent.command, authorized=authorized)
        if decision != "permit":
            return PipelineResult(intent, decision, False, False, False, "policy denied")

        # 2. Build record bound to the agent's public key + domain, then ML-DSA sign.
        record = build_record(self.agent_id, self.identity.public_key,
                              self.identity.alg, intent, decision)
        signature = self.identity.sign(record.signing_bytes())

        # 3. Commit to the tamper-evident log (nonce dedup).
        try:
            entry = self.log.commit(record, signature)
        except DuplicateNonce:
            return PipelineResult(intent, decision, False, False, False, "duplicate nonce (replay)")

        # 4. Verify before actuating: signature under the CREDITED (bound) key, pk-binding
        #    consistency, log inclusion, and policy==permit.
        credited_pk = bytes.fromhex(record.agent_pk_hex)
        sig_ok = verify(record.mldsa_alg, record.signing_bytes(), signature, credited_pk)
        binding_ok = (record.agent_pk_hex == self.identity.public_key.hex())
        inclusion_ok = self.log.prove_and_verify_inclusion(entry)
        policy_ok = (record.policy_decision == "permit")
        verified = sig_ok and binding_ok and inclusion_ok and policy_ok
        if not verified:
            return PipelineResult(intent, decision, True, False, False,
                                  f"verify failed sig={sig_ok} bind={binding_ok} incl={inclusion_ok}")

        # 5. Actuate the emulated device.
        transition = self.device.call_service(intent.command)
        return PipelineResult(intent, decision, True, True, True, "actuated", transition)


def propose_intent(device: str, command: str, context: str, ollama_model: str | None = None) -> ActuationIntent:
    """The untrusted-oracle hook. With ollama_model set, the LLM is *consulted* but never trusted;
    here we record its proposal and still pass it through the guard. Defaults to a fixed intent so
    the demonstrator runs without a model pull."""
    if ollama_model:
        try:
            import ollama  # optional
            ollama.chat(model=ollama_model,
                        messages=[{"role": "user", "content": f"Propose smart-home action for: {context}"}])
        except Exception:
            pass  # untrusted + optional: failure to consult the oracle does not affect safety
    return ActuationIntent(device=device, command=command, context_hash=context_hash(context))


if __name__ == "__main__":
    with MLDSAIdentity("ML-DSA-65") as ident:
        pipe = ProvenancePipeline("home-llm-agent", ident)
        for dev, cmd, auth in [("light.kitchen", "turn_on", False),
                               ("input_boolean.front_door", "turn_on", False),   # unlock, unauthorized
                               ("input_boolean.front_door", "turn_on", True)]:    # unlock, authorized
            intent = propose_intent(dev, cmd, context=f"user asked to {cmd} {dev}")
            res = pipe.run(intent, authorized=auth)
            print(f"{dev:30s} {cmd:9s} auth={auth!s:5s} -> decision={res.policy_decision:6s} "
                  f"verified={res.verified!s:5s} actuated={res.actuated!s:5s} ({res.reason})")
        print("device final state:", pipe.device.state, "| log size:", len(pipe.log))
