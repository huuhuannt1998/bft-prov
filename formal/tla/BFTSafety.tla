------------------------------ MODULE BFTSafety ------------------------------
\* PQ-BFT-Prov Phase 2 — Task 3: BFT-safety (J1) of the signature-based quorum consensus.
\* Abstract model (Apalache): a vote is a vote (the ML-DSA validity is Tamarin's job, Task 4; here
\* ValidVote is abstract per the joint-property spec J3). Single-view single-actuation-decision core.
\* Checks: Agreement (no two conflicting actuations committed) and Integrity (a committed actuation
\* carries >= f+1 honest votes -> the Byzantine minority cannot actuate alone).
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
    votes,        \* votes[r] = set of actuation values replica r has voted for
    \* @type: Set(Str);
    committed     \* committed actuation values

Honest == Replicas \ Byzantine
QuorumSize == (2 * F) + 1

\* @type: (Str) => Int;
VoteCount(v) == Cardinality({ r \in Replicas : v \in votes[r] })
\* @type: (Str) => Int;
HonestVoteCount(v) == Cardinality({ r \in Honest : v \in votes[r] })

HasQuorum(v) == VoteCount(v) >= QuorumSize

Init ==
    /\ votes = [ r \in Replicas |-> {} ]
    /\ committed = {}

\* Honest replica votes for a single value (no equivocation): only if it has not yet voted.
HonestVoteStep(r, v) ==
    /\ r \in Honest
    /\ votes[r] = {}
    /\ votes' = [ votes EXCEPT ![r] = {v} ]
    /\ UNCHANGED committed

\* Byzantine replica votes arbitrarily and may equivocate (vote for multiple values).
ByzVoteStep(r, v) ==
    /\ r \in Byzantine
    /\ votes' = [ votes EXCEPT ![r] = votes[r] \cup {v} ]
    /\ UNCHANGED committed

\* Commit a value once it carries a quorum certificate (2f+1 votes).
CommitStep(v) ==
    /\ HasQuorum(v)
    /\ committed' = committed \cup {v}
    /\ UNCHANGED votes

Next ==
    \/ \E r \in Replicas, v \in Values : HonestVoteStep(r, v)
    \/ \E r \in Replicas, v \in Values : ByzVoteStep(r, v)
    \/ \E v \in Values : CommitStep(v)

\* ---- Invariants (J1) ----
\* AGREEMENT: at most one actuation value is ever committed (no conflicting actuations).
Agreement == Cardinality(committed) <= 1

\* INTEGRITY: every committed actuation carries >= f+1 honest votes.
Integrity == \A v \in committed : HonestVoteCount(v) >= (F + 1)

\* Type sanity for Apalache.
TypeOK ==
    /\ votes \in [ Replicas -> SUBSET Values ]
    /\ committed \subseteq Values
=============================================================================
