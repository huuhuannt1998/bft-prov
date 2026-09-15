---------------------------- MODULE BFTSafetyInductive ----------------------------
\* Phase 4 Task 5: general-N safety of the signature-based quorum consensus via an INDUCTIVE INVARIANT,
\* rather than bounded model-checking at fixed N. Same single-shot model as BFTSafety.tla.
\*
\* Strategy: Agreement alone is not inductive. We strengthen it with two auxiliary invariants:
\*   (HonestVotesOnce)  an honest replica votes for at most one value;
\*   (CommittedHasQuorum) every committed value carries a 2f+1 quorum of voters.
\* The inductive step for Agreement then rests ONLY on quorum intersection: at N = 3f+1 any two 2f+1
\* quorums share at least f+1 voters, hence at least one HONEST voter, who by HonestVotesOnce cannot have
\* voted for two distinct committed values. This argument never uses the concrete value of N beyond
\* N = 3f+1, so a machine-checked inductive invariant generalizes along the N = 3f+1 line (all f).
EXTENDS Integers, FiniteSets

CONSTANTS
    \* @type: Set(Int);
    Replicas,
    \* @type: Set(Int);
    Byzantine,
    \* @type: Int;
    F,
    \* @type: Set(Str);
    Values

VARIABLES
    \* @type: Int -> Set(Str);
    votes,
    \* @type: Set(Str);
    committed

Honest == Replicas \ Byzantine
QuorumSize == (2 * F) + 1
\* @type: (Str) => Int;
VoteCount(v) == Cardinality({ r \in Replicas : v \in votes[r] })
HasQuorum(v) == VoteCount(v) >= QuorumSize

Init ==
    /\ votes = [ r \in Replicas |-> {} ]
    /\ committed = {}

HonestVoteStep(r, v) ==
    /\ r \in Honest
    /\ votes[r] = {}
    /\ votes' = [ votes EXCEPT ![r] = {v} ]
    /\ UNCHANGED committed

ByzVoteStep(r, v) ==
    /\ r \in Byzantine
    /\ votes' = [ votes EXCEPT ![r] = votes[r] \cup {v} ]
    /\ UNCHANGED committed

CommitStep(v) ==
    /\ HasQuorum(v)
    /\ committed' = committed \cup {v}
    /\ UNCHANGED votes

Next ==
    \/ \E r \in Replicas, v \in Values : HonestVoteStep(r, v)
    \/ \E r \in Replicas, v \in Values : ByzVoteStep(r, v)
    \/ \E v \in Values : CommitStep(v)

\* ---- the safety goal ----
Agreement == Cardinality(committed) <= 1

\* ---- typing + auxiliary invariants (the strengthening) ----
TypeOK ==
    /\ votes \in [ Replicas -> SUBSET Values ]
    /\ committed \in SUBSET Values
HonestVotesOnce == \A r \in Honest : Cardinality(votes[r]) <= 1
CommittedHasQuorum == \A v \in committed : VoteCount(v) >= QuorumSize
FaultBound == Cardinality(Byzantine) <= F /\ Cardinality(Replicas) = (3 * F) + 1

\* ---- the inductive invariant ----
IndInv ==
    /\ TypeOK
    /\ FaultBound
    /\ HonestVotesOnce
    /\ CommittedHasQuorum
    /\ Agreement

\* Integrity follows from CommittedHasQuorum + the fault bound: a 2f+1 quorum has >= f+1 honest voters.
Integrity == \A v \in committed : Cardinality({ r \in Honest : v \in votes[r] }) >= (F + 1)

\* WeakInv drops the two auxiliary invariants; it is NOT inductive (a state with a committed value but
\* no quorum, or an honest replica voting twice, steps out of it). The CTI it yields is the benign
\* strengthening signal, not a reachable protocol violation.
WeakInv == TypeOK /\ FaultBound /\ Agreement
==============================================================================
