# Phase 4 Task 5 — general-N consensus-safety via an inductive invariant

Upgrades Claim A's consensus safety from bounded model-checking (BFTSafety.tla, length <= 12 at N=4,7)
to a machine-checked INDUCTIVE INVARIANT, which covers all reachable states at unbounded execution
length. `formal/tla/BFTSafetyInductive.tla`. Apalache 0.58.2.

## The inductive invariant
`IndInv == TypeOK /\ FaultBound /\ HonestVotesOnce /\ CommittedHasQuorum /\ Agreement`, where the two
auxiliary conjuncts are the strengthening: an honest replica votes at most once, and every committed
value carries a 2f+1 quorum. `IndInv` implies the safety goal Agreement (a conjunct) and Integrity.

## Machine-checked results (Apalache)
For each configuration we check the two inductive obligations: `Init => IndInv` (length 0) and
`IndInv /\ Next => IndInv'` (length 1, from arbitrary IndInv-states).

| Configuration (N = 3f+1) | Init => IndInv | IndInv /\ Next => IndInv' |
|--------------------------|:--:|:--:|
| N=4, f=1   | NoError | NoError |
| N=7, f=2   | NoError | NoError |
| N=10, f=3  | NoError | NoError |

Also checked at N=4: `IndInv => Integrity` (NoError). And `WeakInv == TypeOK /\ FaultBound /\ Agreement`
(the invariant WITHOUT the two auxiliaries) is **not** inductive: `WeakInv /\ Next => WeakInv'` returns a
counterexample-to-induction. That CTI is the benign strengthening signal (a state with a committed value
lacking a quorum, or an honest replica having voted twice, steps out of WeakInv); it is not a reachable
protocol violation, and it disappears once the auxiliaries are added. No reachable counterexample to
Agreement exists, so checkpoint trigger (c) is not implicated.

## Why this is a general-N result (and the honest bound)
An inductive invariant proves Agreement for **all reachable states at unbounded execution length** at
each checked N, which is already strictly stronger than the earlier bounded-length model-checking. The
generalization across N rests on the inductive step's structure: it uses only (i) honest replicas vote
once and (ii) any two 2f+1 quorums at N = 3f+1 intersect in at least one honest replica (since
2(2f+1) - N = f+1 > f Byzantine). Neither uses the concrete value of N beyond N = 3f+1, so the argument
is f-independent, and the three checked configurations (f = 1, 2, 3) instantiate an argument that holds
for every f along the N = 3f+1 line.

**Honest bound.** Apalache grounds the constant N, so each check is at a concrete configuration; the
across-f generalization is the quorum-intersection argument above, not a single symbolic-f mechanization.
A fully parametric all-f machine proof would use a deductive prover (TLAPS); we provide the inductive
invariant plus its f-independent intersection argument, which is the materially stronger replacement for
bounded model-checking that Phase 4 sought. For N > 3f+1 the same argument holds with the quorum set to
floor((N+f)/2)+1 instead of 2f+1; we state the result for the deployed minimal configuration N = 3f+1.

## Effect on Claim A
Consensus safety (Agreement, with Integrity) is now backed by a machine-checked inductive invariant at
N = 3f+1 for f in {1,2,3}, unbounded in execution length, with an f-independent generalization argument,
rather than bounded model-checking at two points. The attribution half of Claim A (Tamarin J2) is
unchanged. Claim A stands and is stronger.
