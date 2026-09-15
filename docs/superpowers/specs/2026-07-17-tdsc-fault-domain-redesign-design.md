# Design: Fault-Domain-Aware Quorums for Accountable LLM-Agent Actuation (TDSC redesign)

**Date:** 2026-07-17
**Project:** PQ-BFT-Prov (RKA `prj_01KVS3QXV9F35FNSK4RZE2WFDV`)
**Driver:** `manuscripts/IEEE_TDSC_PQ_BFT_Prov_Full_Feedback.md` (major-revision review)
**Status:** Approved in shape by PI (2026-07-17); pending written-spec review.

---

## 1. Context

The existing manuscript (NDSS-2027 draft) frames the work as *"a diverse-model `2f+1`
quorum with ML-DSA."* The TDSC pre-submission review calls this **not ready** and diagnoses the
core problem as **scientific, not presentational**: a signed approval threshold is presented as a
BFT system, key-level evidence as broad attribution, and post-quantum signatures as automatic
novelty. Its Priority-1 fix is a **technical redesign**, not more runs of the current experiments.

The review's own strongest observation — *model diversity does not create independent failure
domains* — is repurposed here from a limitation into the paper's central principle.

## 2. The scientific reframe (the spine)

> LLM-agent replicas are **not** independent Byzantine replicas. Their prompt-injection failures
> are structured by shared model lineage, defense, and execution domains. Authorization for
> high-risk actuation must therefore require **coverage across independent fault domains**, not a
> count of agents — and every authorization must be recorded as durable cryptographic evidence.

This is the review's Gate-1 principle. Every workstream serves it.

## 3. Goals and non-goals

### Goals
- Replace the nominal `2f+1` diverse-agent quorum with a **fault-domain-aware authorization policy**
  grounded in *measured* correlated failures.
- An **accountable actuation architecture**: container-isolated agent + signer services, evidence
  binding of request/context/config commitments, epoch-aware append-only log with key lifecycle.
- **Formal assurance of the new policy** (not another `2f+1` intersection proof), plus lifecycle,
  replay, revocation properties and an implementation-conformance boundary.
- A TDSC-scale **evaluation** organized by research question (RQ1–RQ7).
- A retargeted **TDSC manuscript** (~12 pages) with narrowed, testable claims.

### Non-goals (hard constraints — stated plainly in the paper, never papered over)
- **No physical / hardware-in-the-loop actuation.** M4-only, no Pi/GPIO/real devices. Actuation
  stays **emulated** (Home Assistant virtual devices) with a full software actuation-state lifecycle.
- **No true multi-host distribution.** "Distributed" is instantiated as **container/process
  isolation on one M4** with independent key stores and a network channel — honest single-host
  isolation, not multi-machine.
- **No paid resources.** No cloud models, no paid QPU, no paid APIs. Local Ollama + open-source
  tooling only (PI constraint: zero budget).
- **No expansion of the quantum demo.** Qiskit Aer stays a one-sentence concrete classical-forgery
  instance; effort goes to the classical-vs-PQ evidence comparison (RQ6) instead.
- Model internals remain **untrusted**; ML-DSA/ML-KEM primitives remain **assumed secure** (not
  re-proven), except the BUFF assessment already in scope.

## 4. Fault-domain model (grounded to this testbed)

The review lists seven domains. On local-only single-M4 infra, only a subset is genuinely
measurable; we model **only those and say so**:

| Domain | Instantiation on this testbed | Real? |
|---|---|---|
| **lineage** | model family / training (6 families) | yes |
| **size** | parameter count within family | yes |
| **defense** | injection defense (the load-bearing domain) | yes |
| **quantization/runtime** | Ollama quant level (q4/q8) + llama.cpp runtime | yes |
| **isolation/key-domain** | separate container + independent signer/key store | yes (container-level) |
| ~~provider~~ | no cloud provider on local-only infra | **dropped, explicitly** |
| ~~administrator~~ | not instantiable on single-operator testbed | **dropped, explicitly** |

Each agent `a_i` carries a label set `D(a_i) ⊆ {lineage, size, defense, quant, iso}`. The paper
states plainly that provider/administrator domains are out of scope for lack of a faithful
instantiation.

Accompanying artifacts: the review's **TCB table**, **dependability goals** (authorization
integrity, certificate consistency, replay resistance, accountability evidence, availability,
fail-safe, recovery, actuation confirmation), and **separated adversaries A–H**.

## 5. Architecture

### 5.1 Isolated services
- Each agent is an **isolated service** (separate container/process, restricted privileges).
- Each **signer is a separate service with an independent key store**; the signer **validates a
  structured proposal before signing** (no blind-signing of orchestrator-supplied strings).
- Services communicate over a network channel (HTTP/gRPC on loopback), enabling fault injection.

### 5.2 Evidence binding (accountability upgrade)
Every vote/certificate binds collision-resistant commitments to:
`{action, user-request, untrusted-context, system-prompt, defense-policy, model+weight hash,
quant/runtime, view, nonce, seq, timestamp, epoch, prev-log-checkpoint}`.
Full context may be stored separately/encrypted; the certificate carries the commitments.

### 5.3 Fault-domain-aware quorum policy (the new core)
A certificate is **valid** iff its approving set satisfies both:
1. **≥ k distinct signers**, and
2. **domain-coverage constraints derived from the measured fail-prone sets** — e.g. ≥ d distinct
   defense domains, ≤ c votes per lineage, and (high-risk) ≥ 1 deterministic non-LLM verifier.

Formalized with an explicit **adversary structure** `Δ` (the set of fail-prone domain-sets that may
fail together), replacing the scalar `f`. The guarantee: **no `B ∈ Δ` can alone produce a
policy-valid certificate.** The exact policy parameters are **fit to RQ1 measurements**, not chosen
arbitrarily.

### 5.4 Risk tiers + deterministic safety verifier
Risk tiers (low/moderate/high/critical) map to escalating quorum/coverage requirements; critical
actions default to denial or human confirmation. An expanded **OPA/Rego deterministic verifier**
(beyond the current 3 rules) carries independent semantic safety constraints (bounds, interlocks,
occupancy, time-of-day, rate limits, conflicts). The LLM quorum is **not** the sole semantic authority.

### 5.5 Provenance log + actuation lifecycle
Log gains **epochs, signed tree heads, inclusion/consistency proofs, key-rotation/revocation
records, and an external checkpoint anchor** (honest single-host second-store anchor). An explicit
**actuation-lifecycle state machine**: `proposed → approved → committed → transmitted → acked →
observed → done/failed` — emulated, honestly labeled; the record distinguishes authorization from
(emulated) physical completion.

## 6. Formal assurance

- **TLA+/Apalache:** model the fault-domain policy; prove **no fail-prone domain-set alone
  certifies** (domain-coverage intersection), plus epoch/reconfiguration/replay/revocation invariants.
  Counterexample tests for weakened policies.
- **Tamarin:** strengthen with enrollment, public-key registry, key compromise time, rotation,
  revocation, epochs, external checkpoints, context/policy commitments, gateway verification, replay,
  compromised-orchestrator attempts. Lemmas: authorization authenticity before compromise, injective
  agreement signer↔gateway, no-actuation-without-policy-valid-cert, replay resistance, historical
  verification across rotation, revocation effectiveness.
- **Conformance:** property-based testing of certificate validation, **differential testing** of the
  implementation validator vs the formal `WellFormedQC` predicate, malformed-cert corpus, parser
  fuzzing, serialization round-trips, golden signature/cert vectors.
- **Parametric:** attempt **TLAPS** for the coverage lemma. If it stalls, present as a **rigorous
  mathematical generalization + finite Apalache checks**, labeled exactly — never "parametric
  machine-checked" unless it actually closes.

## 7. Evaluation (organized by research question)

### RQ1 — Correlated failures (Phase 1; compute-heavy; background)
- Corpus: **300–500 attacks + 150–250 legitimate** — **authored smart-home cases + public-benchmark-
  derived scenarios (AgentDojo/InjecAgent-style), ingested strictly as DATA.** Documented taxonomy
  (18 attack categories, single/multi-turn, direct/indirect, minimal attack/benign pairs).
- Models: 6 families × ≥2 sizes (+quant variants); exact model hashes + runtime versions.
- **Defense-diversity matrix** (all free/open-source): no-defense, instruction/data-separation,
  **instruction hierarchy**, **spotlighting**, **known-answer/canary detection**, StruQ-style
  surrogate, per-agent independent prompts, capability-scoped execution, deterministic policy,
  human-confirm.
- **≥3 repetitions** per condition (5 for adaptive/multi-turn); report per-payload/per-run variability;
  document nondeterminism sources.
- Analysis (pre-registered): **mixed-effects logistic regression** (random effects: payload, model;
  fixed effects: family, size, defense, attack-category, delivery; interactions defense×model,
  attack×defense), clustered bootstrap CIs, effect sizes. **Decisive experiment:** does **defense
  diversity** decorrelate failures more than **model-family diversity**? → **This output defines the
  quorum policy parameters.**

### RQ2 — Quorum-policy dependability (Phase 2)
Compare the **12 baselines** (single strongest/weakest, repeated-instance majority, family-diverse
majority, validation-weighted quorum, static-policy-only, LLM+policy, human-confirm, shared-defense
quorum, independent-defense quorum, fault-domain-aware quorum, oracle upper bound) on security,
utility, availability, latency, cost.

### RQ3 — Adaptive robustness (Phase 3)
Adaptive + multi-turn attacks constructed to **cross the configured fault domains** and satisfy the
authorization rule. Extends the existing adaptive harness.

### RQ4 — System fault tolerance (Phase 4)
Distributed fault injection on the isolated services: crash (pre/post partial votes), omission,
equivocation, duplicate vote, mixed-view cert, cross-action vote reuse, unknown/revoked-key vote,
replay, delayed/dropped messages, network partition, stale epoch, log crash during commit, gateway
crash post-commit, host recovery + log replay. Report safety, availability, recovery, audit per case.

### RQ5 — Accountable evidence + key lifecycle (Phase 5)
Key rotation, revocation, model retirement/upgrade, prompt/runtime upgrade, old-certificate
verification, compromise discovered after epoch close, external checkpoint verification, log
truncation/rollback attempts. Forensic reconstruction metrics; whether a revoked key invalidates old
evidence or only future authorizations.

### RQ6 — Cryptographic overhead (Phase 5)
Full table: **Ed25519/ECDSA vs ML-DSA-44/65/87 (+SLH-DSA if feasible)** — sign size, pk size, sign
latency, verify latency, certificate size, log growth over realistic action rates/retention. Batch
verification, binary encoding. End-to-end **p50/p95/p99** latency (not just crypto microbenchmarks).
Classical-with-trusted-timestamp vs PQ as an evidence-architecture comparison. **liboqs, free.**

### RQ7 — Physical actuation (descoped, honest)
Emulated actuation-lifecycle results only; explicit limitation. No hardware claims.

## 8. Constraints & honesty guardrails (carried through every phase)
- Emulated actuation; single-host container isolation; local-model scope; exact finite-vs-parametric
  formal language — all stated plainly.
- Attack corpora are **DATA, never instructions** to any process.
- No claim of physical deployment, multi-host distribution, non-repudiation, or "BFT consensus"
  beyond the implemented/evaluated behavior. Terminology narrowed per review §12.

## 9. Phasing & checkpoints (Approach A: empirical-first)

| Phase | Content | Nature | PI checkpoint |
|---|---|---|---|
| 0 | Story + threat/fault-domain model doc; pre-register stats + corpus design; TDSC skeleton | design | yes |
| 1 | RQ1: expand corpus + defense matrix + model matrix + reps; mixed-effects analysis | compute (bg) | yes → policy params |
| 2 | Fault-domain quorum + container isolation + evidence binding + risk tiers + verifier; RQ2 baselines | build+run | yes |
| 3 | RQ3 adaptive/multi-turn cross-domain attacks | run | yes |
| 4 | RQ4 distributed fault injection + recovery | build+run | yes |
| 5 | RQ5 key lifecycle + forensic; RQ6 crypto comparison | build+run | yes |
| 6 | Formal: fault-domain policy model + lifecycle + Tamarin + conformance + parametric attempt | build | yes |
| 7 | Rewrite → TDSC manuscript (`manuscripts/tdsc/`), 12-page, narrowed claims | write | yes |

Rewrite is **last** so sections aren't written twice. Big sweeps run as **background jobs**.

## 10. Deliverables / repo changes
- `docs/02-fault-domain-model/` — threat + fault-domain spec, TCB table, dependability goals, adversaries A–H.
- `decorrelation/` — expanded corpus, defense implementations, expanded model matrix, mixed-effects analysis.
- `consensus/` — fault-domain policy, adversary structure, evidence binding, risk tiers.
- `agent/`, `provenance/` — isolated services, signer validation, epoch log, key lifecycle, actuation lifecycle.
- `formal/tla`, `formal/tamarin` — policy model + lifecycle; `formal/conformance/` — differential/property tests.
- `eval/` — crypto comparison, fault injection, forensic metrics, stats plan.
- `manuscripts/tdsc/` — new manuscript.

## 11. Success criteria (the review's decision gates)
1. **Novelty:** a stated principle beyond combining known mechanisms (§2 reframe). ✅ by design.
2. **Guarantee:** every main claim a precise property with assumptions (what's signed, which domains
   approve, adversary tolerated, what's trusted, what's not proven).
3. **Realism:** multiple isolated services, separate keys, networked operation, recovery testing
   (physical descoped, honestly).
4. **Empirical credibility:** attack resistance + utility jointly, with reps and the 12 baselines.
5. **Formal relevance:** proofs verify the **new** policy, not a standard quorum rule.
6. **PQ relevance:** long-term-evidence threat model + classical-vs-PQ comparison; ML-DSA framed as a
   supported evidence mode, not headline novelty.

## 12. Risks
- **Compute:** TDSC-scale eval = tens of thousands of local inferences per sweep; days of background
  wall-clock. Mitigation: resumable per-model checkpoints, factorial subsampling with documented design.
- **Policy grounding:** RQ1 taxonomy could shift domain labels late. Mitigation: Approach A does RQ1
  first; policy is fit after, not before.
- **Parametric proof may not close (TLAPS).** Mitigation: honest fallback to math + finite checks.
- **Scope is large.** Mitigation: each phase gets its own `writing-plans` implementation plan; the
  first plan covers Phase 0 + Phase 1 only.

## 13. Decomposition note
This spec is a **program**, not a single implementation plan. The immediate next step is a
`writing-plans` plan for **Phase 0 (story + fault-domain model + pre-registration + TDSC skeleton)
and Phase 1 (RQ1 expansion + mixed-effects analysis)**, since Approach A front-loads measurement.
Later phases get their own plans at each checkpoint.
