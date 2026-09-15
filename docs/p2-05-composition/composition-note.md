# Composition Note — combining Apalache BFT-safety and Tamarin attribution (Phase 2, Task 5)

Mission `mis_01KVWZY3TK1WJHWD7P6AZV2F2G`, Task 5. **PI directive:** treat the composition as a
first-class deliverable, not an afterthought — *"that seam is where the joint property can silently
weaken."* This note states the shared interface, the assumptions each prover discharges vs. assumes,
and why `J1 ∧ J2` follows for a real actuation **without a gap at the seam**.

## 1. The two results
- **J1 (Apalache, `formal/tla/`):** Agreement (no two conflicting actuations committed) + Integrity
  (a committed actuation carries ≥ f+1 honest votes). Verified at N=4/f=1 and N=7/f=2.
- **J2 (Tamarin, `formal/tamarin/cert_attribution_*.spthy`):** every actuation binds to a quorum
  certificate of 2f+1 distinct ML-DSA votes, ≥ f+1 honest, injective and non-repudiable under the
  quantum adversary (forgeable in the classical instance, holds in the PQC instance).

Each prover is used where it is strong (FV footing dec_01KVS3WK60WAPV8TS7QBZ108BM): Apalache for the
stateful Byzantine-quorum reachability argument, Tamarin for the cryptographic attribution under a
Dolev–Yao + quantum adversary. Neither tool does the other's job well — hence two provers.

## 2. The shared interface: `WellFormedQC`
Both provers reason about the **same** certificate object via one predicate (Task-1 §J3):

```
WellFormedQC(act, v, Q)  :=  |Q| = 2f+1  ∧  distinct(Q)  ∧  (∀ i ∈ Q. ValidVote(i, act, v))
```

The two provers read **`ValidVote`** at different abstraction levels — this is the seam:

| | Apalache (J1) | Tamarin (J2) |
|--|---------------|--------------|
| `ValidVote(i, act, v)` | **abstract**: replica i is recorded as having voted for `(act, v)` (`v ∈ votes[i]`) | **cryptographic**: a verifying ML-DSA signature `verifyQ(σ_i, ⟨pk_i, act, v⟩, pk_i) = true` |
| `distinct(Q)` | distinct replica ids | distinct public keys `pk_i` (`Neq`) |
| `|Q| = 2f+1` | `Cardinality ≥ 2f+1` | three distinct verified votes (core case 2f+1=3) |
| Byzantine bound | `Byzantine ⊆ Replicas, |Byzantine| ≤ f` | `AtMostOneByzantine` (f=1), Byzantine key leaked |

## 3. Why the readings coincide (no gap)
The composition is sound iff Apalache's abstract `ValidVote` is **refined** by — never weaker than —
Tamarin's cryptographic `ValidVote`. Two directions:

1. **Crypto ⇒ abstract (soundness of abstraction).** A Tamarin-valid vote (a verifying ML-DSA
   signature on `⟨pk_i, act, v⟩`) can only be produced by agent i's `Honest_Vote` rule (ML-DSA
   unforgeable, honest `sk_i` not leaked) — so it *implies* "i voted for `(act, v)`", exactly
   Apalache's abstract fact. The consensus reference impl (`consensus/certificate.py:well_formed`)
   computes precisely this predicate, so the artifact all three (Apalache, Tamarin, code) reason about
   is the same. **No vote counted by Apalache lacks a cryptographic witness in Tamarin.**
2. **Abstract ⇒ crypto (no over-counting).** Apalache counts a replica's vote once (honest replicas
   vote once; distinctness on ids). Tamarin enforces distinctness on **keys** and the
   `AtMostOneByzantine` bound, so the ≤ f Byzantine of J1 corresponds to the ≤ f leaked keys of J2.
   The per-vote BUFF binding (`⟨pk_i, act, v⟩`) guarantees a Tamarin vote cannot be re-counted under a
   different id/`(act,v)` — so Apalache's id-distinct count is not inflated by crypto-level
   re-attribution. (This is exactly what the certificate-BUFF memo, `docs/p2-04-cert-buff`, closes.)

Therefore a single object satisfying `WellFormedQC(act, v, Q)` simultaneously witnesses J1 (2f+1
agreement ⇒ Agreement + Integrity) and carries J2 (2f+1 ML-DSA attribution ⇒ injective
non-repudiation). **`J1 ∧ J2` holds for every committed actuation**, which is the joint property.

## 4. Shared assumptions (stated once, used by both)
- **N ≥ 3f+1**, quorum **2f+1**; honest signing keys uncompromised; ≤ f Byzantine.
- ML-DSA EUF-CMA + single-signer BUFF (Phase 1; 2025/900) — Tamarin side; Apalache assumes only that a
  counted vote is authentic, which (1) above discharges.
- Certificate-BUFF (mix-and-match / set-substitution / cross-view replay) closed by the structural
  `WellFormedQC` checks (Task 4) — this is what makes the abstraction sound; **if those checks were
  dropped, the seam would leak** (an Apalache "vote" without a real cryptographic witness), which is
  the precise failure mode the PI flagged.
- Safety only (asynchrony); liveness needs partial synchrony (out of scope of the joint *safety*
  property).

## 5. Where the seam could silently weaken (and the guard against it)
The one way `J1 ∧ J2` could be *claimed* but false: Apalache counts a vote that has **no** Tamarin
cryptographic witness — e.g. if the implementation's quorum check did not verify each ML-DSA signature
and the per-vote `⟨pk_i, act, v⟩` binding, or accepted duplicate/cross-view votes. The guard is that
**`consensus/certificate.py:well_formed` performs exactly the §2 checks**, and both the Tamarin model
(Task 4) and the Apalache abstraction (Task 3) are pinned to that same predicate. Any future change to
the quorum rule must be reflected in all three or the composition is void — this is a maintenance
invariant, recorded here deliberately.
