# PQ-BFT-Prov Phase 2 — Joint-Property Specification (Task 1)

**Deliverable for Task 1** of mission `mis_01KVWZY3TK1WJHWD7P6AZV2F2G`.
Extends the Phase-1 single-agent core (`docs/01-threat-model/system-and-threat-model.md`) to an
**N-agent post-quantum BFT quorum**. This spec is **normative** for the consensus reference impl
(`consensus/`, Task 2), the Apalache BFT-safety model (`formal/tla/`, Task 3), the Tamarin
certificate-attribution model (`formal/tamarin/`, Task 4), and the composition note (Task 5).

Provenance: Phase-2 direction `dec_01KVWZ2RY2TDP7BQCPSKETY3RN`; FV footing
`dec_01KVS3WK60WAPV8TS7QBZ108BM` (Tamarin attribution + Apalache BFT-safety); hardware
`dec_01KVWZV01Z23GWW41451NH96X6` (M4-only, emulated). Honesty: "first verified realization +
systematization," **not** a conceptual first — quorum-gated actuation and the correlated-fault
observation are deVadoss et al. (arXiv:2504.14668), **not** claimed here.

---

## 1. The fusion point (what makes this not "stapled")

A single artifact — the **post-quantum quorum certificate `QC`** — is simultaneously:
- **(BFT)** the *safety witness*: evidence that ≥ 2f+1 agents agreed on the actuation, so no f
  Byzantine agents alone could have produced it; and
- **(PQC)** the *attribution token*: an aggregate of ≥ 2f+1 **ML-DSA**-signed votes, non-repudiable
  and forgery/re-attribution-resistant under a quantum adversary.

BFT defends **decision integrity at runtime** (no single injected agent actuates); PQC defends
**attribution over time** (harvest-now-decrypt-later / forgery-resistant record). `QC` is where they
meet. **The consensus MUST be signature-based with ML-DSA votes** (dec_…ETY3RN, scope_boundaries):
signature-free BFT would decouple the two and make the contribution stapled. The Phase-2 certificate
is an **aggregate of individual ML-DSA signatures**; threshold ML-DSA is a stretch goal, not core.

---

## 2. System model

### 2.1 Principals
| Symbol | Component | Trust |
|--------|-----------|-------|
| `R = {1..N}` | replica set of **N agents** (each = an LLM oracle + a signing identity) | up to **f Byzantine**; **N ≥ 3f+1** |
| `pk_i, sk_i` | agent i's ML-DSA keypair | `sk_i` secret to i |
| `G` | OPA/Rego policy guard | trusted (Phase 1) |
| `L` | tamper-evident provenance log | trusted for integrity (Phase 1) |
| `D` | emulated Home Assistant virtual device | endpoint (emulated) |

**Byzantine agent** = prompt-injected / hijacked / hallucinating: it may vote arbitrarily, equivocate,
or stay silent. As in Phase 1 the LLM is an **untrusted oracle**; we never verify its reasoning. A
Byzantine agent's *signing key* may be used adversarially (it controls its own votes) but the keys of
**honest** agents are not compromised.

### 2.2 Quorum parameters
- **N ≥ 3f+1** (classic BFT bound). **Quorum size = 2f+1.** Any two quorums intersect in ≥ f+1 agents,
  hence in ≥ 1 honest agent (quorum intersection — the safety backbone).
- A certificate `QC(a, v)` for actuation `a` in view/round `v` is a set of **2f+1 valid ML-DSA-signed
  votes** `{ σ_i = Sign(sk_i, ⟨a, v, "approve"⟩) }` from **distinct** agents, each binding `pk_i`
  (the Phase-1 BUFF rule, lifted per agent).

### 2.3 Protocol (signature-based, PBFT/HotStuff-derived — detailed in Task 2)
```
 propose(a, v)         a leader proposes actuation a in view v
 vote_i               honest i checks a against its local policy view; if approve, broadcasts
                      ⟨a, v, approve⟩ signed σ_i = Sign(sk_i, ⟨a, v, approve⟩)
 QC(a, v)             any agent that collects 2f+1 distinct valid votes forms the certificate
 commit/actuate       QC(a,v) -> Phase-1 provenance commit (QC is the signed record) -> OPA gate
                      -> Actuate(a). The actuation binds to QC, not to a single signature.
```

### 2.4 Events / action facts (shared prover vocabulary)
- `Propose(a, v)` — actuation `a` proposed in view `v`.
- `HonestVote(i, a, v)` — honest agent i signs an approve-vote for `(a, v)`.
- `FormQC(a, v, Q)` — a certificate over agent-set `Q`, `|Q| = 2f+1`, is formed for `(a, v)`.
- `Commit(a, v)` / `Actuate(a)` — the certified actuation is committed to `L` and actuated.

---

## 3. The JOINT property (formal)

Let honest agents be `H ⊆ R`, `|H| ≥ N − f ≥ 2f+1`.

### J1 — BFT Safety (Agreement / no-bad-actuation) — Apalache obligation
> **(Agreement)** No two conflicting actuations are committed in the same view:
> `∀ a, a', v. Commit(a, v) ∧ Commit(a', v) ⇒ a = a'.`
>
> **(Integrity)** Every committed actuation was approved by a full quorum, hence by **≥ f+1 honest
> agents**: `∀ a, v. Commit(a, v) ⇒ ∃ Q, |Q| = 2f+1 ∧ (∀ i ∈ Q. Voted(i, a, v)) ∧ |Q ∩ H| ≥ f+1.`

Consequence (the property the mission states): **no f Byzantine agents can cause an actuation a 2f+1
honest quorum would reject** — because any certificate carries ≥ f+1 honest votes, an actuation the
honest majority opposes cannot reach 2f+1. Verified by **Apalache** at N=4/f=1 (then N=7/f=2), under
documented assumptions (partial synchrony for liveness; safety holds under asynchrony).

### J2 — Quantum-Attribution-Binding over the certificate — Tamarin obligation
> Every `Actuate(a)` binds to a **valid post-quantum certificate** `QC(a, v)` consisting of 2f+1
> authentic ML-DSA votes from distinct agents, and this binding is **injective and non-repudiable
> under the quantum adversary**: the actuation cannot be (i) **forged** (executed with no genuine
> 2f+1-quorum behind it), (ii) **replayed** to a second actuation, or (iii) **re-attributed** to a
> different actuation, view, or agent-set.

This lifts Phase-1's P3 from a single signature to the **aggregate certificate**. Verified by
**Tamarin** under the relativized quantum adversary (classical sigs forgeable, ML-DSA retained), and
gated by the **certificate-level BUFF** question (§4).

### J3 — The unifying claim (composition, Task 5)
> The **same** `QC` object witnesses J1 (it is the 2f+1-agreement evidence Apalache reasons about)
> and carries J2 (it is the 2f+1 ML-DSA attribution token Tamarin reasons about). The joint property
> `J1 ∧ J2` holds for an actuation iff a single well-formed `QC(a, v)` exists. The **shared interface**
> both provers must agree on is the predicate **`WellFormedQC(a, v, Q)` := |Q| = 2f+1 ∧ distinct(Q) ∧
> (∀ i ∈ Q. ValidVote(i, a, v))`** — Apalache treats `ValidVote` abstractly (an agent voted),
> Tamarin treats it cryptographically (a verifying ML-DSA signature binding `pk_i`). Task 5 must show
> these two readings of `WellFormedQC` coincide on the certificate object (no gap at the seam).

---

## 4. Certificate-level BUFF (the novel coupled question — Task 4, gates J2)

Phase 1 established that single-signature attribution needs exclusive ownership + message-bound, which
ML-DSA provides (Meyer–Struck–Weishäupl, ePrint 2025/900, λ-bit EO), with the pk-binding transform
(`attribution_buff_fixed.spthy`) as belt-and-suspenders. **Phase 2 must re-ask this for the AGGREGATE
certificate**, where it is *not* automatic:

- **Caveat (ePrint 2025/427, lit_01KVX3Q9V67JM4MKTEBKTMMHTX):** the exclusive-ownership hierarchy that
  holds for single signers does **not** carry to threshold/aggregate signatures unless the scheme is
  also **robust**. Our certificate is a *concatenation-aggregate* of independent ML-DSA signatures (not
  a threshold signature), so each component sig keeps single-signer EO — but the **certificate as a
  whole** must additionally resist: (a) **mix-and-match** (assembling a "valid" QC from votes for
  *different* `(a, v)`); (b) **agent-set substitution** (re-attributing a QC to a different `Q`);
  (c) **vote replay across views**. These are certificate-level analogues of BUFF.
- **Design rule (seed from `attribution_buff_fixed`):** each vote signs the *full context*
  `⟨pk_i, a, v⟩` (agent key + actuation + view bound in), and `WellFormedQC` checks all 2f+1 votes
  carry the **same** `(a, v)` and **distinct** `pk_i`. Task 4 will machine-check that this closes
  (a)–(c) in Tamarin, and the memo will state whether any residual property needs threshold-signature
  robustness (escalation trigger (a) if it fails with no transform).

---

## 5. Threat model (delta from Phase 1)
- **Network:** Dolev–Yao. **Quantum adversary** by primitive relativization (classical forgeable,
  ML-DSA intact) — unchanged from Phase 1 §4.2.
- **Byzantine agents:** ≤ f, fully adversarial (equivocate, withhold, vote maliciously, use own keys).
- **Out of scope:** > f compromised agents (breaks the BFT bound — disclosed assumption); breaking
  ML-DSA; verifying LLM reasoning; physical actuation (emulated); paid/real QPU.
- **Decorrelation assumption (Task 6 earns or refutes it):** the f-bound is only meaningful if agent
  faults are *independent*. A prompt injection that flips one agent must not flip > f of them. This is
  an **assumption to be measured**, not assumed true — high cross-model jailbreak transfer (effective
  f → N) is a **publishable negative result** (checkpoint trigger (d)), not a number to massage.

## 6. Assumptions register (carried to the Phase-2 gate)
1. N ≥ 3f+1; honest keys uncompromised; certificate = 2f+1 distinct valid ML-DSA votes.
2. ML-DSA single-signer BUFF holds (Phase 1, 2025/900); **certificate-level** BUFF is Task 4's to
   establish (mix-and-match / set-substitution / cross-view replay), mindful of 2025/427.
3. Apalache closes J1 at N=4/f=1 (≥ N=7/f=2 ideally) without state explosion (else trigger (b)).
4. The `WellFormedQC` interface reading coincides across Apalache and Tamarin (else trigger (c)).
5. Fault-independence is **measured** (Task 6), not assumed; emulated actuation; M4 timing = feasibility.
