# PQ-BFT-Prov — System and Threat Model (Phase 1 core)

**Deliverable for Task 1** of mission `mis_01KVS3YJBEHQ3GD6Y5N6ZTJTSD`.
**Scope:** the single-agent core (Phase 1). The BFT quorum (Phase 2) is out of scope here and is
referenced only where it changes a definition.
**Status:** specification; the property names and fact vocabulary below are normative for the Tamarin
model (`formal/tamarin/`, Task 2) and the BUFF assessment (`docs/03-buff-memo/`, Task 3).

Provenance: direction `dec_01KVS3W370R01JTK2YP513DK62`; FV footing `dec_01KVS3WK60WAPV8TS7QBZ108BM`
(Tamarin primary); RQ1 `dec_01KVS3WSXK7FJMF3RE7D8E6QTJ`; RQ2 `dec_01KVS3X0TDT90Q3B5K4T8S8AEB`;
hardware `dec_01KVWZV01Z23GWW41451NH96X6` (M4-only, emulated actuation).

---

## 1. Informal goal

A smart-home LLM agent decides to actuate a device ("unlock the front door", "set boiler to 80 °C").
We want a **non-repudiable, post-quantum binding** so that:

> Every actuation that physically (here: *virtually*) occurs corresponds to **exactly one** authentic,
> policy-compliant decision by an identified agent, and that correspondence cannot be **forged**
> (an actuation with no genuine decision behind it) or **re-attributed** (a genuine actuation pinned
> to the wrong decision, agent, or device) — even by an adversary holding a quantum computer.

We call this property **injective attribution-binding**. It is the Phase-1 centerpiece (RQ2). The threat
that motivates it (RQ1) is that a *classical*-signature provenance chain admits exactly such a forgery
under a quantum adversary (Shor breaks RSA/ECDSA), whereas a PQC (ML-DSA) chain does not.

**Honesty note.** The idea of gating actuation on an attestation, and of modeling a quantum adversary
symbolically by relativizing signature unforgeability, are **not** claimed as novel here (cf. deVadoss
et al., arXiv:2504.14668, and prior PQC-protocol symbolic analyses). The contribution is the *first
machine-checked realization* of injective attribution-binding terminating at an actuation action fact,
plus the explicit BUFF dependency analysis.

---

## 2. System model

### 2.1 Principals and components

| Symbol | Component | Trust | Realization (this project) |
|--------|-----------|-------|----------------------------|
| `A`  | **LLM agent** (the "brain") | **UNTRUSTED oracle.** May be benign or adversarial (prompt-injected). Its internal reasoning is *never* verified. | Ollama local model behind MCP + smolagents |
| `G`  | **Policy guard / automaton** | **TRUSTED, verified.** Decides whether a proposed tool-call is policy-compliant; the agent has no say. | OPA/Rego runtime; the automaton it instantiates is what Tamarin proves preserves attribution |
| `L`  | **Provenance log** | TRUSTED for *integrity* (tamper-evident), not for secrecy | Merkle log (pymerkle), entries **ML-DSA-signed** (not Ed25519) |
| `V`  | **Gateway / verifier** | TRUSTED | Verifies the signed decision→actuation record before releasing the command |
| `D`  | **Device / actuator** | endpoint; **EMULATED** | Home Assistant virtual device (logged command) |
| `sk_A, pk_A` | agent signing keypair (ML-DSA) | `sk_A` secret to `A` | liboqs ML-DSA-44/65/87 |

The **distinguished honest agent** whose decisions we attribute is `A`. The adversary may register its
own keypairs and act as additional (dishonest) agents.

### 2.2 The provenance-to-actuation chain (happy path)

```
 (1) A: decide x      AgentDecide(A, x)         x = (device, command, nonce, context-hash)
 (2) A -> G: request to actuate x, signed:  m1 = <x>            σ1 = Sign(sk_A, m1)
 (3) G: evaluate policy φ(x).  If φ(x) = permit:  PolicyApprove(G, A, x)
 (4) G/L: append entry e = <x, pk_A, σ1, decision=permit> to L; commit:  ProvenanceCommit(e)
 (5) V: verify Vrfy(pk_A, m1, σ1) ∧ e ∈ L ∧ decision=permit  ->  release
 (6) D: actuate.   Actuate(A, x)   <-- the FIRST-CLASS ACTION FACT the property terminates at
```

`Actuate(A, x)` is modeled as a first-class observable action fact (a logged virtual-device command),
**not** a message — this is what makes the correspondence terminate "at the physical world."

### 2.3 The agent-decision event, the hop, the action fact (mission-mandated definitions)

- **Agent-decision event** `AgentDecide(A, x)`: agent `A` commits to actuation intent `x`. `x` carries a
  fresh `nonce` (uniqueness) and a `context-hash` binding the decision to its triggering context.
- **Provenance-chain hop** `ProvenanceCommit(e)`: a signed, logged transition carrying `x`, the asserting
  agent's public key `pk_A`, and the agent's signature `σ1`, appended to the tamper-evident log `L`.
- **Physical-actuation action fact** `Actuate(A, x)`: the (emulated) device state change. The security
  property is a correspondence *from* `Actuate` *back to* a unique `AgentDecide`.

---

## 3. Security properties (formal statements)

We use Lowe's correspondence hierarchy. Let `Actuate(A, x)` and `AgentDecide(A, x)` be event facts in a
trace. Write `⟶` for "precedes in the trace".

### P1 — Authentication (aliveness + weak agreement)
> For every `Actuate(A, x)` there exists `AgentDecide(A, x)` with `AgentDecide(A, x) ⟶ Actuate(A, x)`.

No actuation without a genuine prior decision *by the named agent* on *that* `x`. Forgery-resistance.

### P2 — Policy-compliance binding
> Every `Actuate(A, x)` is preceded by `PolicyApprove(G, A, x)`, and `PolicyApprove(G, A, x)` only fires
> when the verified guard automaton evaluates `φ(x) = permit`.

The actuation that happens is one the *policy* allowed — the untrusted agent cannot route around `G`.

### P3 — **Injective attribution-binding** (the core, RQ2)
> For every `Actuate(A, x)` there is a **unique** `AgentDecide(A, x)` preceding it; i.e. two distinct
> `Actuate(A, x)` facts cannot share one `AgentDecide(A, x)` (no replay to a second actuation), and one
> `Actuate(A, x)` cannot be matched to a decision by a *different* agent `A' ≠ A`, a *different* intent
> `x' ≠ x`, or a *different* device than the one in `x` (no re-attribution).

P3 is **injective agreement** specialized to terminate at the actuation fact, plus the
*non-re-attribution* clause. In Tamarin: an `injective` correspondence lemma keyed on `(A, x)` with
`x` carrying the fresh nonce.

### P3 decomposed for the BUFF dependency (feeds Task 3)
Non-re-attribution requires more than EUF-CMA unforgeability. Re-attribution attacks that EUF-CMA does
*not* rule out:

- **(a) Re-attribution to another key** (breaks *exclusive ownership* / DEO): adversary takes the honest
  `(m1, σ1)` and produces `pk_A'` (its own, or a colliding key) such that `Vrfy(pk_A', m1, σ1) = true`.
  Then the same actuation record verifies under the attacker's identity, or the honest agent's
  actuation is claimed by the attacker. EUF-CMA says nothing about *other* keys.
- **(b) Message re-binding** (breaks *message-bound signatures* / MBS): adversary exhibits `m1' ≠ m1`
  with `Vrfy(pk_A, m1', σ1) = true`, re-attributing the same signature/log entry to a different intent
  `x'` (different device or command).
- **(c) Re-signability / malleability** (breaks *non-re-signability* / S-CEO, S-DEO): adversary, possibly
  knowing `sk` of a *related* key, derives a new signature on the same `(m, pk)` that the log treats as a
  distinct authentic hop, enabling duplicate or laundered attribution.

These are exactly the **BUFF** properties (Beyond UnForgeability Features; Cremers–Düzlü–Fiedler–Günther–
Janson, IEEE S&P 2021; Fiedler et al. ePrint **2020/1525**): **exclusive ownership (CEO/DEO), message-bound
signatures (MBS), non-re-signability (NR)**. **P3's non-re-attribution clause structurally depends on
ML-DSA providing (a)–(c).** Whether it does is the explicit go/adjust question of Task 3; if not, the
candidate sub-contribution is a **BUFF-lifting transform** (e.g. bind `pk_A` and a domain/context tag
into the signed message and the log-entry hash, à la the BUFF generic transform: sign `H(pk ‖ m)`).

### P4 — Non-repudiation (corollary of P1+P3 + tamper-evident `L`)
> Given `Actuate(A, x)`, the log `L` yields a publicly checkable proof that `A` (and only `A`) authorized
> `x`, which `A` cannot later deny and no one else can fabricate.

---

## 4. Threat model

### 4.1 Network adversary (baseline)
Standard **Dolev–Yao**: the adversary controls the network — intercept, drop, reorder, replay, inject —
and knows all public keys. It cannot break cryptography "for free": that is governed by §4.2.

### 4.2 Quantum adversary by **primitive relativization** (mission-mandated; precedent-cited, not novel)
We do **not** model qubits in the symbolic prover. We model the *consequence* of a cryptographically
relevant quantum computer (CRQC) as a **relativization of the signature unforgeability assumption**:

- **Classical signatures (RSA/ECDSA) — BROKEN.** The adversary is given a `Forge_classical` capability:
  an equational/rule-level oracle that, from a public key `pk` alone, produces a signature `σ` on any
  message `m` such that `Vrfy_classical(pk, m, σ) = true`. (This abstracts Shor's algorithm recovering the
  private key; RQ1/Task 4 instantiates it concretely in Qiskit Aer on a toy modulus.)
- **PQC signatures (ML-DSA) — INTACT.** ML-DSA unforgeability is retained: no `Forge` rule. Signatures are
  the usual symbolic `sign/verify` with `verify(pk, m, sign(sk, m)) = true` and *no* adversary rule that
  yields `sign(sk, m)` without `sk`. **Primitive security is assumed, not proven** (Formosa-Crypto /
  liboqs); §3's BUFF clause is the one place we examine a property *beyond* EUF-CMA.

This single knob (classical-forge present, PQC-forge absent) is what makes the two model instances differ:
the classical chain admits a P1/P3 counterexample; the PQC chain satisfies P1–P4 (subject to Task-3 BUFF).

### 4.3 Compromise model
- **Agent compromise (in scope conceptually, bounds RQ2):** `A`'s *reasoning* may be adversarial
  (prompt injection) — this is *expected* and handled by `G`/P2, **not** by trusting `A`. We do **not**
  model leakage of `A`'s signing key `sk_A` as the core case (that is a key-management assumption); an
  optional lemma may explore `sk_A` reveal to show the log still attributes correctly up to the reveal.
- **Guard `G`, gateway `V`, log `L` integrity:** trusted. `L` is tamper-evident: the adversary cannot
  alter or drop committed entries without detection (Merkle inclusion/consistency).
- **Out of scope:** side channels, fault injection, breaking ML-DSA/ML-KEM primitives, verifying the
  LLM's internal computation, physical-hardware actuation (actuation is **emulated**).

### 4.4 Adversary goals (the negations we test)
- **G-forge:** cause `Actuate(A, x)` with no genuine `AgentDecide(A, x)` — negates P1.
- **G-reattribute:** cause a genuine actuation to verify against a different agent/intent/device —
  negates P3 via BUFF attacks (a)/(b)/(c).
- **G-bypass:** cause `Actuate(A, x)` with `φ(x) = deny` — negates P2.
- **G-replay:** reuse one decision to drive two actuations — negates P3 injectivity.

---

## 5. Mapping to the Tamarin model (Task 2 contract)

| Spec element | Tamarin encoding |
|--------------|------------------|
| `AgentDecide(A,x)`, `PolicyApprove(G,A,x)`, `ProvenanceCommit(e)`, `Actuate(A,x)` | action facts (labels) on rules |
| fresh `nonce` in `x` | `Fr(~n)` |
| ML-DSA sign/verify | functions `sign/2`, `verify/3`, equation `verify(pk(sk), m, sign(sk,m)) = true`; **no** forge rule |
| classical sign/verify (baseline instance) | same signature theory **plus** an adversary rule `[ ] --> [ Out(sign(sk_of(pk), m)) ]` style `Forge_classical` capability keyed on `pk` only |
| tamper-evident log | persistent facts `!LogEntry(e)`; consistency by construction |
| **P1** | `All A x #i. Actuate(A,x)@i ==> Ex #j. AgentDecide(A,x)@j & j<i` |
| **P2** | `... ==> Ex #k. PolicyApprove(G,A,x)@k & k<i` |
| **P3 (injective)** | `All A x #i1 #i2. Actuate(A,x)@i1 & Actuate(A,x)@i2 ==> #i1=#i2` **and** unique-decision agreement keyed on `(A,x)` |
| BUFF (a)/(b)/(c) | modeled by whether the equational theory lets a signature verify under a *different* `pk` or a *different* `m`; the baseline ML-DSA theory must be checked against Task-3 findings before P3 is declared proven |

**Gating rule (PI directive):** P3 must be declared *proven* only under primitive assumptions that the
Task-3 BUFF memo confirms ML-DSA actually satisfies (or that the BUFF-lifting transform restores). A clean
Tamarin run on an over-optimistic signature theory (e.g. one that silently assumes exclusive ownership
ML-DSA may not have) does **not** count as RQ2 proven.

### 5.1 Termination guard (PI directive)
Keep the model to the **core single-actuation case** (one honest agent, bounded roles, one device class).
If the P3 injective lemma fails to terminate, that is a **checkpoint trigger** (reformulate / bound
sessions / restrict), not something to grind on. RAM-hungry lemmas on the M4 are a known risk.

---

## 6. Assumptions register (carried into the gate)
1. ML-DSA EUF-CMA holds (verified-impl assumption; not re-proven).
2. ML-DSA provides — or a BUFF-lifting transform restores — exclusive ownership, message-bound, and
   non-re-signability sufficient for P3. **← the one assumption Task 3 must discharge.**
3. Tamarin can express P3 as an injective correspondence terminating at `Actuate` and the core lemma
   terminates. **← Task 2 must demonstrate; non-termination ⇒ escalate.**
4. Guard/gateway/log are trusted and the log is tamper-evident.
5. Actuation is emulated; M4 timing is "feasibility on a capable hub" only.
6. The four-pillar intersection remains unscooped (monitor `jrn_01KVS3T4SNGEK8SVP5MRYCVRMY` triggers).

---

## 7. What Phase 1 must show at the gate
- **Baseline (classical) instance:** a Tamarin **counterexample trace** to P1/P3 using `Forge_classical`
  (the quantum forgery of the classical chain) — RQ1 symbolic side, mirrored concretely by Qiskit (Task 4).
- **PQC instance:** P1, P2, **P3 (injective attribution-binding)**, P4 hold for the single-actuation core,
  *under Task-3-validated primitive assumptions*.
- **BUFF memo:** go/adjust on whether ML-DSA suffices or needs the lifting transform (Task 3).
- **Four-pillar table:** PQ-BFT-Prov occupies a cell no nearest-competitor work occupies (Task 7).
