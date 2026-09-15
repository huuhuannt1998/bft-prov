# Phase 2 Task 3 — Apalache BFT-safety results (J1)

Apalache 0.58.2 (+ OpenJDK 21), Apple M4. Abstract single-view consensus model
(`BFTSafety.tla`): honest replicas vote once (no equivocation); Byzantine replicas (≤ f) vote
arbitrarily and may equivocate; a value commits on a 2f+1 quorum. `ValidVote` is abstract here — its
cryptographic meaning (a verifying ML-DSA vote) is Tamarin's obligation (Task 4); the shared
`WellFormedQC` interface (Task 1 §J3) is what lets the two combine (Task 5).

## Invariants
- **Agreement** (`Cardinality(committed) <= 1`) — no two conflicting actuations are ever committed.
- **Integrity** (`∀ v ∈ committed : HonestVoteCount(v) >= f+1`) — every committed actuation carries
  ≥ f+1 honest votes, so the Byzantine minority cannot actuate alone.

## Results — N = 4, f = 1 (N = 3f+1, quorum = 3)  [`MC_N4.tla`]
| Check | Outcome | Time |
|-------|---------|------|
| `Agreement`, length 12 | **NoError** (holds) | ~110 s |
| `Integrity`, length 12 | **NoError** (holds) | ~23 s |
| Non-vacuity (`committed = {}` as inv) | **Violated at state 4** → a commit IS reachable, so the invariants above are non-trivial | ~2 s |

Both safety invariants hold and the model genuinely reaches committed states (non-vacuous). This is
the J1 requirement.

## Results — N = 7, f = 2 (N = 3f+1, quorum = 5)  [`MC_N7.tla`]
| Check | Outcome | Time |
|-------|---------|------|
| `Agreement`, length 8 | **NoError** (holds) | ~9 s |
| `Integrity`, length 8 | **NoError** (holds) | ~5 s |

Both safety invariants hold at N=7/f=2 as well (the mission's "ideally" target), at bounded length 8.
(N=4/f=1 was checked to length 12; N=7 to length 8 — both well beyond the few steps needed to reach a
commit, per the non-vacuity check.)

## Notes
- macOS has no `timeout(1)` (use `gtimeout` from coreutils, or run unbounded) — relevant for scripting
  Apalache runs.
- The model checks **safety** (Agreement/Integrity), which holds under asynchrony. **Liveness**
  (a decision is eventually reached) needs partial synchrony and is out of the safety core, as stated
  in the joint-property spec.
- Negative-control intuition: safety relies on quorum intersection (N ≥ 3f+1 ⇒ any two 2f+1 quorums
  share ≥ f+1 ≥ 1 honest replica). The non-vacuity check confirms the model is not trivially safe by
  never committing.
