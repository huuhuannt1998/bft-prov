# Fault-Domain Threat Model — PQ-BFT-Prov (TDSC redesign)

**Status:** Phase 0 canonical reference. Every later phase (corpus/defense-matrix design,
quorum-policy implementation, formal modeling, manuscript) cites this document rather than
re-deriving the taxonomy, adversaries, TCB, or dependability goals.

**Source of truth:** this document operationalizes `docs/superpowers/specs/2026-07-17-tdsc-fault-domain-redesign-design.md`
§3–§5 and `manuscripts/IEEE_TDSC_PQ_BFT_Prov_Full_Feedback.md` §7.1, §7.3, §11.4. Where the two
disagree in wording, the review (`IEEE_TDSC_PQ_BFT_Prov_Full_Feedback.md`) is the authoritative
source for adversary/goal/TCB language, and the design spec is authoritative for which domains
are instantiable on this testbed.

---

## 1. Fault-domain taxonomy

The review's threat-model revision (§6, §7) lists seven candidate fault domains along which
LLM-agent replicas can fail together rather than independently: lineage, size, defense,
quantization/runtime, isolation/key-domain, provider, and administrator. This testbed is
**local-only, single-M4, single-operator** infrastructure (spec §3, non-goals). Two of the seven
domains have no faithful instantiation under that constraint and are **dropped, explicitly**,
rather than modeled with a placeholder or a synthetic stand-in. Modeling a domain that cannot be
measured would produce an authorization policy tuned against a fiction; the paper states the drop
plainly instead.

| Domain | Instantiation on this testbed | Real? |
|---|---|---|
| **lineage** | model family / training lineage (6 model families in the RQ1 matrix) | yes |
| **size** | parameter count within a family (≥2 sizes per family, + quant variants) | yes |
| **defense** | injection-defense mechanism applied to the agent (the load-bearing domain — RQ1's decisive comparison is defense-diversity vs. model-family-diversity) | yes |
| **quantization/runtime** | Ollama quantization level (q4/q8) + llama.cpp runtime version | yes |
| **isolation/key-domain** | separate container/process per agent, with an independent signer service and independent key store | yes (container-level isolation, not multi-host — see §5) |
| ~~provider~~ | would require multiple cloud/hosting providers | **dropped, explicitly** — no cloud provider exists on local-only infra; there is nothing to diversify over |
| ~~administrator~~ | would require multiple independent human operators | **dropped, explicitly** — not instantiable on a single-operator testbed; there is exactly one administrator, so "administrator diversity" cannot be measured or defended |

Each agent `a_i` in the design carries a label set `D(a_i) ⊆ {lineage, size, defense, quant, iso}`
drawn only from the five real domains above. The fault-domain-aware quorum policy (design spec
§5.3) is defined, and its coverage parameters are fit, entirely over this reduced five-domain set.
The paper states plainly, wherever the taxonomy is presented, that provider and administrator
domains are out of scope for lack of a faithful instantiation on this infrastructure — this is a
scope limitation carried into the honesty boundary (§5 below), not a claim that provider- or
administrator-level correlated failure does not matter.

---

## 2. Separated adversaries (A–H)

The review's diagnosis (§7.1) is that a single monolithic threat model conflates capabilities that
should be reasoned about independently. Each adversary below is stated with its capability and
with what the fault-domain-aware design does, and does not, defend against it.

### A. Content attacker

Controls untrusted calendar, email, document, notification, web, or retrieval content, and
attempts to manipulate model decisions through it (prompt injection). This is the adversary the
defense-diversity domain and the RQ1 corpus (300–500 attacks, 18 categories, single/multi-turn,
direct/indirect) are built to measure. The design defends against A by requiring domain-coverage
across independent defenses (≥ d distinct defense domains, per design spec §5.3) so that a single
injection technique effective against one defense mechanism cannot alone satisfy the quorum, and
by requiring a deterministic non-LLM verifier (OPA/Rego) for high-risk actions, so semantic safety
does not rest on the LLM alone. It does **not** claim to prevent all successful injections — RQ1
explicitly measures the residual attack-success rate per defense/model combination, and RQ3
constructs adaptive attacks designed to cross the configured domain boundaries.

### B. Compromised model agent

Can emit an arbitrary vote and rationale, but cannot use another agent's signing key (each signer
is a separate service with an independent key store, per design spec §5.1). The design defends
against B by requiring ≥ k distinct signers plus domain-coverage constraints for certificate
validity: a single compromised agent, or several compromised agents confined to the same domain
values, cannot alone produce a policy-valid certificate (the adversary-structure guarantee, design
spec §5.3 — no `B ∈ Δ` can alone certify). It does not defend against a compromise that spans
enough independent domains to satisfy the coverage rule; that is the residual risk the RQ1
measurements and RQ3 adaptive attacks are designed to characterize, not eliminate.

### C. Compromised host or orchestrator

Can modify inter-process messages, reorder requests, replay records, or attempt to invoke signing
services directly. The review notes the current (pre-redesign) system effectively excludes this
adversary. The redesign narrows, but does not close, that gap: the signer is a separate isolated
service that validates a structured proposal and constructs its own canonical vote record rather
than blindly signing an orchestrator-supplied string (design spec §5.1), and RQ4's fault-injection
suite exercises host/orchestrator-adjacent failures (mixed-view certificates, cross-action vote
reuse, unknown/revoked-key votes, gateway crash post-commit). The design explicitly does **not**
defend against full host compromise on the machine hosting a given container: isolation here is
process/container separation on one host, not multi-machine or hardware-attested isolation (see
§5, honesty boundary).

### D. Network adversary

Can delay, drop, replay, duplicate, and reorder messages between the isolated services (agent,
signer, gateway, log), which now communicate over a real network channel (HTTP/gRPC on loopback,
design spec §5.1) rather than in-process calls. The design defends against D via nonce, sequence
number, view, and epoch commitments bound into every certificate (design spec §5.2), giving replay
resistance and detectable reordering, and RQ4 directly fault-injects delay/drop/replay/duplicate/
reorder/partition conditions and reports safety, availability, and recovery per case. It does not
defend against an adversary that can also compromise a host outright (that capability belongs to
C) or against loss of the physical network path beyond what the fault-injection harness exercises.

### E. Key-compromise adversary

Compromises some signing keys, at a known or unknown time. The design defends against E in two
ways: the domain-coverage rule bounds how many votes from any one key-domain/lineage can count
toward a certificate (≤ c votes per lineage, design spec §5.3), so compromise of a single signer's
key is insufficient on its own to satisfy quorum; and the epoch-aware key lifecycle (rotation,
revocation records, RQ5) lets the system determine whether a revoked key invalidates only future
authorizations or also older evidence, and supports forensic reconstruction when compromise is
discovered after an epoch has closed. It does not defend against compromise of enough
independently-keyed signers, spanning enough domains, to satisfy the coverage rule simultaneously —
that residual case is what the domain-coverage parameters, fit from RQ1, are chosen to make rare.

### F. Future cryptanalytic adversary

Obtains historical records today and later gains the ability to forge signatures under a broken
classical scheme. The design's response is architectural, not purely cryptographic: PQ signature
algorithms (ML-DSA-44/65/87) are offered as a supported evidence mode alongside classical
signatures, compared head-to-head on cost (RQ6), and the provenance log carries an external
checkpoint anchor for later independent verification of historical entries (design spec §5.5).
ML-DSA/ML-KEM primitives are treated as assumed-secure building blocks, not re-proven by this
work (design spec §3, non-goals) — the design defends against F to the extent that PQ signatures
remain valid, and gives an honest classical-vs-PQ evidence-architecture comparison rather than a
claim that PQ signatures are automatically necessary or sufficient (spec's non-goal on the Qiskit
demo: no expansion of the quantum break demonstration itself).

### G. Malicious or compromised operator

Attempts to delete, reorder, or fabricate log entries. This adversary corresponds directly to the
**administrator** fault domain, which §1 records as **dropped, explicitly** for this testbed: there
is exactly one operator/administrator, so the design cannot claim administrator-diversity as a
defense, and does not claim to. What the design does provide against a subset of G's actions is
log-level: append-only structure, signed tree heads, inclusion/consistency proofs, and an external
checkpoint anchor (design spec §5.5) make undetected deletion or rollback of already-anchored
entries harder even for someone with host access, and RQ5 evaluates log truncation/rollback
attempts directly. It does **not** defend against an administrator who controls the single host
before entries are anchored, or against operator-level denial of service — that is the honest
consequence of running on single-operator infrastructure, stated as a scope limit rather than a
solved threat.

### H. Physical-device adversary

Causes the device to reject, ignore, or falsely acknowledge a command. Because actuation is
**emulated** (Home Assistant virtual devices, design spec §3, non-goals — no physical or
hardware-in-the-loop actuation), the design's response to H is limited to the software layer: the
actuation-lifecycle state machine (`proposed → approved → committed → transmitted → acked →
observed → done/failed`, design spec §5.5) distinguishes authorization from acknowledgement from
observed completion, so a false-ACK-shaped failure is representable and loggable in the emulated
lifecycle. The design explicitly does **not** defend against, or make any claim about, genuine
hardware fault behavior, physical tampering, or real actuator failure modes — RQ7 is descoped and
reports emulated-lifecycle results only, with no hardware claim (design spec §7, RQ7).

---

## 3. Trusted computing base (TCB)

The review (§7.2) observes that the pre-redesign TCB — floor, log, gateway, enrollment process,
keys, implementation, and model fidelity — is too large and undifferentiated to reason about. The
redesign narrows and itemizes trust per component (review §11.4):

| Component | Trusted for | May fail by | Protected by |
|---|---|---|---|
| Model agent | Nothing semantic | Injection, hallucination | Quorum, policy |
| Signing service | Correct binding | Host compromise | Isolation, attestation |
| Gateway | Certificate enforcement | Software compromise | Small TCB, tests |
| Log | Append consistency | Deletion, rollback | Signed checkpoints |
| Device | State transition | Failure, false ACK | State verification |

Two entries in the "Protected by" column state the design's *target* mechanism rather than a
mechanism already fully realized on this testbed: "isolation" for the signing service is
container/process separation on one host, not hardware attestation — no attestation hardware or
TEE is used here (consistent with the honesty boundary, §5); "state verification" for the device
is bounded by the emulated actuation lifecycle (§2, adversary H), not by observation of real
physical state. Model agent is explicitly trusted for **nothing semantic**: all semantic-safety
weight is carried by the quorum's domain-coverage rule and the deterministic policy verifier, never
by any single agent's output.

---

## 4. Dependability goals

The review (§7.3) defines the minimum dependability goals the redesigned system must state and be
evaluated against. Restated here as the canonical list every later phase (formal modeling, RQ2–RQ5
evaluation, manuscript claims) must trace back to:

- **Authorization integrity:** no action executes without a policy-valid certificate.
- **Certificate consistency:** all signatures bind the same action, request, context commitment,
  view, and epoch.
- **Replay resistance:** one authorization cannot cause multiple unintended actuations.
- **Accountability evidence:** the log identifies the registered keys and configuration
  commitments used for authorization.
- **Availability:** legitimate actions complete when enough fault domains are available.
- **Fail-safe behavior:** high-risk actions default to denial or human confirmation under
  insufficient quorum.
- **Recovery:** the system safely reconfigures after key rotation, model retirement, or host
  failure.
- **Actuation confirmation:** the record distinguishes requested, authorized, transmitted,
  acknowledged, and physically observed states.

RQ2 (quorum-policy dependability) and RQ4 (system fault tolerance) are the evaluation phases
responsible for producing evidence against these goals; RQ5 (accountable evidence + key lifecycle)
is responsible for recovery and accountability-evidence specifically. No goal above is claimed as
satisfied by this document — this document only fixes the goal statements so later phases measure
against a stable target.

---

## 5. Honesty boundary

Three properties of this testbed are **scope limits on what can be measured or exercised**, not
threats the design claims to defend against, and every later phase must state them the same way
rather than let them read as solved problems. First, actuation is **emulated**: physical devices
are Home Assistant virtual devices, so the actuation-lifecycle state machine can record and be
evaluated on `transmitted → acked → observed` transitions, but no claim is made about genuine
hardware behavior, physical tampering resistance, or real actuator failure modes (this bounds
adversary H, §2, and RQ7 is descoped accordingly — emulated-lifecycle results only, explicit
limitation, no hardware claim). Second, isolation is **single-host container/process isolation**:
each agent and each signer runs as a separate container with its own key store on one M4, which is
enough to make key-domain separation and network-channel communication real and fault-injectable
(RQ4), but it is not multi-machine or multi-VM distribution and it does not defend against an
adversary capable of compromising the underlying host itself (this bounds adversary C, §2, and is
why "distributed" and "BFT" are used narrowly, per the review's terminology guidance, §12). Third,
scope is **local-model-only**: the model matrix (RQ1) covers 6 open-weight families run locally via
Ollama/llama.cpp, with no cloud models, no paid QPU, and no paid APIs (spec §3, non-goals) — this is
also why the **provider** fault domain is dropped from the taxonomy in §1, since there is no second
provider to diversify against. None of these three limits is a defended threat with a residual-risk
measurement attached; they are boundaries of what this testbed can instantiate at all, and the
manuscript must present them as such rather than qualify them away.
