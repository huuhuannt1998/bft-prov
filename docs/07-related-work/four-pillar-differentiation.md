# Task 7 — Four-Pillar Related-Work Differentiation

Grounded in the planning-phase novelty verdicts (jrn_01KVS3T4MHSD56CPPNHY0TNP2Y,
jrn_01KVS3T4SDR1FDJKE212TAMWKS). The four pillars:

- **P-Prov** — binds an **LLM-agent's** policy-compliant *decision* into the provenance (not just a
  device command or a transport-layer identity).
- **P-PQC** — uses **post-quantum** signatures (ML-DSA) for the provenance/attestation.
- **P-Proof** — a **machine-checked** proof of an *injective attribution-binding / non-repudiation*
  property (symbolic, stateful), not just an empirical or hand-argued claim.
- **P-Act** — terminates at a **physical actuation** event (CPS), with overhead measured on a device.

`●` = fully addressed, `◐` = partial/adjacent, `○` = absent.

| Work | P-Prov (agent decision) | P-PQC | P-Proof (machine-checked attribution) | P-Act (physical actuation) |
|------|:--:|:--:|:--:|:--:|
| **AIP** (arXiv:2603.24775) — agent identity/provenance | ● | ○ | ○ (empirical, not machine-checked) | ○ |
| **HDP / ETDI** — agent delegation/provenance protocols | ● | ○ | ○ | ○ |
| **Smart-Home PQC AKA 2026** — device AKA + ProVerif | ○ (device-AKA, no agent) | ● | ◐ (proves AKA, **not** decision-attribution) | ○ |
| **Kao et al.** quantum-safe audit (arXiv:2512.00110) | ◐ (audit logs) | ● | ◐ (reductionist notions, audit not actuation) | ○ |
| **QSC** — quantum-safe signing/credentials | ○ | ● | ○ | ○ |
| **VeriGuard / Pro2Guard** — formally-verified agent guardrails | ● (guard) | ○ | ◐ (verifies guard policy, **not** PQC attribution-to-actuation) | ○ |
| **From Prompt to Physical Actuation** (arXiv:2604.27267) | ◐ | ○ | ○ (names the repudiation gap, only **threat-models** it) | ● |
| **PQ-BFT-Prov (this work)** | ● | ● | ● (Tamarin: injective attribution-binding under a quantum adversary) | **◐ (emulated)** |

## The cell PQ-BFT-Prov occupies — stated honestly

Every adjacent work drops at least one pillar; **no prior work holds P-Prov + P-PQC + P-Proof
simultaneously**, and that intersection is PQ-BFT-Prov's contribution: *the first machine-checked
proof of injective correspondence between an LLM-agent's policy-compliant decision and an actuation
event, under a quantum adversary, with end-to-end post-quantum (ML-DSA) provenance.* The Tamarin
result (classical chain forgeable, ML-DSA chain attribution-binding; `formal/tamarin/`) plus the
machine-checked BUFF-in-context dependency (`docs/03-buff-memo`) instantiate this cell concretely.

**Honest caveat on P-Act (per dec_01KVWZV01Z23GWW41451NH96X6).** This project is **M4-only with
EMULATED Home Assistant actuation** — so it does **not** fully occupy the physical-actuation pillar
(`◐`, not `●`). Only *From Prompt to Physical Actuation* targets true physical actuation, and it
merely threat-models the repudiation gap rather than closing it with a proof. We therefore do **not**
claim the physical-CPS pillar as a strength; the contribution is carried by **P-Proof × P-PQC ×
P-Prov** — the verified post-quantum attribution binding — with actuation emulated and disclosed.
This is consistent with the project's "first verified realization + systematization, not a conceptual
first" framing: the quorum-gated-actuation idea, the correlated-fault observation, and the
symbolic-quantum-adversary device are **not** claimed novel (precedent: deVadoss et al.,
arXiv:2504.14668; see threat model §1, §4.2).

## What we explicitly do NOT claim as novel
PQC command/log signing in the abstract; agent provenance chains in the abstract; formally verifying
PQC non-repudiation in the abstract; the quantum-adversary symbolic-modeling trick; physical
actuation. Novelty is defended **only** at the sharpened intersection above. Re-check the 2026
preprint space immediately before submission (triggers: jrn_01KVS3T4SNGEK8SVP5MRYCVRMY).
