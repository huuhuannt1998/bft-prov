-------------------------- MODULE BFTSafety_TLAPS --------------------------
(***************************************************************************)
(* P2 #18: a DRAFTED parametric proof (TLAPS) of consensus Agreement for    *)
(* ALL N = 3f+1. STATUS: written but NOT YET machine-verified -- tlapm was   *)
(* not installable in our build environment, so this is a proof SKELETON, a  *)
(* starting point for the future-work parametric proof, not a checked        *)
(* artifact. Do not cite it as machine-checked. The machine-CHECKED result   *)
(* we rely on is the Apalache inductive invariant at N=4/7/10                 *)
(* (BFTSafetyInductive.tla) plus the f-independent quorum-intersection        *)
(* argument; this module formalizes that same argument for tlapm.            *)
(*                                                                         *)
(* Same single-shot model as BFTSafetyInductive.tla. The proof rests on one *)
(* parametric lemma -- any two 2f+1 quorums among >= 3f+1 replicas share an  *)
(* honest replica -- from finite-set cardinality, plus the inductive          *)
(* invariant (honest replicas vote once; committed values carry a quorum).    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, FiniteSetTheorems, TLAPS

CONSTANTS Replicas, Byzantine, F, Values

ASSUME ReplicaAssume ==
    /\ IsFiniteSet(Replicas)
    /\ Byzantine \subseteq Replicas
    /\ F \in Nat
    /\ Cardinality(Byzantine) =< F
    /\ Cardinality(Replicas) >= (3 * F) + 1

Honest == Replicas \ Byzantine
QuorumSize == (2 * F) + 1
Quorums == { Q \in SUBSET Replicas : Cardinality(Q) >= QuorumSize }

VARIABLES votes, committed
vars == << votes, committed >>

VoteCount(v)  == Cardinality({ r \in Replicas : v \in votes[r] })
HasQuorum(v)  == VoteCount(v) >= QuorumSize
Voters(v)     == { r \in Replicas : v \in votes[r] }

TypeOK ==
    /\ votes \in [ Replicas -> SUBSET Values ]
    /\ committed \in SUBSET Values

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

Spec == Init /\ [][Next]_vars

Agreement          == Cardinality(committed) =< 1
HonestVotesOnce    == \A r \in Honest : Cardinality(votes[r]) =< 1
CommittedHasQuorum == \A v \in committed : Voters(v) \in Quorums

IndInv ==
    /\ TypeOK
    /\ HonestVotesOnce
    /\ CommittedHasQuorum
    /\ Agreement

(***************************************************************************)
(* Parametric quorum intersection: the heart of the general-N argument.    *)
(* |Q1 \cap Q2| >= |Q1|+|Q2|-|Replicas| >= (2f+1)+(2f+1)-(3f+1) = f+1 > f,   *)
(* and |Byzantine| =< f, so Q1 \cap Q2 must contain an honest replica.       *)
(***************************************************************************)
LEMMA QuorumIntersect ==
    ASSUME NEW Q1 \in Quorums, NEW Q2 \in Quorums
    PROVE  \E r \in Honest : r \in Q1 /\ r \in Q2
PROOF
  <1> USE ReplicaAssume DEF Quorums, QuorumSize, Honest
  <1>1. IsFiniteSet(Q1) /\ IsFiniteSet(Q2)
        BY FS_Subset
  <1>2. Cardinality(Q1) + Cardinality(Q2)
          =< Cardinality(Q1 \cap Q2) + Cardinality(Replicas)
        BY <1>1, FS_Subset, FS_UnionInter, FS_CardinalityType
  <1>3. Cardinality(Q1 \cap Q2) >= (F + 1)
        BY <1>2, FS_CardinalityType
  <1>4. IsFiniteSet(Q1 \cap Q2) /\ IsFiniteSet(Byzantine)
        BY <1>1, FS_Intersection, FS_Subset
  <1>5. Cardinality((Q1 \cap Q2) \ Byzantine) >= Cardinality(Q1 \cap Q2) - Cardinality(Byzantine)
        BY <1>4, FS_Difference
  <1>6. Cardinality((Q1 \cap Q2) \ Byzantine) >= 1
        BY <1>3, <1>5, FS_CardinalityType
  <1>7. (Q1 \cap Q2) \ Byzantine # {}
        BY <1>6, <1>4, FS_Difference, FS_EmptySet
  <1>8. PICK r \in (Q1 \cap Q2) \ Byzantine : TRUE
        BY <1>7
  <1> QED BY <1>8

(***************************************************************************)
(* The inductive invariant is established and preserved.                   *)
(***************************************************************************)
LEMMA InitInv == Init => IndInv
PROOF
  <1> SUFFICES ASSUME Init PROVE IndInv OBVIOUS
  <1> USE ReplicaAssume DEF Init, IndInv, TypeOK, HonestVotesOnce,
          CommittedHasQuorum, Agreement, Voters, Honest
  <1>1. TypeOK BY FS_EmptySet
  <1>2. HonestVotesOnce BY FS_EmptySet
  <1>3. CommittedHasQuorum OBVIOUS
  <1>4. Agreement BY FS_EmptySet
  <1> QED BY <1>1, <1>2, <1>3, <1>4

LEMMA NextInv == IndInv /\ [Next]_vars => IndInv'
PROOF
  <1> SUFFICES ASSUME IndInv, [Next]_vars PROVE IndInv'
        OBVIOUS
  <1> USE ReplicaAssume DEF IndInv, TypeOK, HonestVotesOnce, CommittedHasQuorum,
          Agreement, Voters, HasQuorum, VoteCount, Quorums, QuorumSize, Honest
  <1>1. CASE \E r \in Replicas, v \in Values : HonestVoteStep(r, v)
        (* an honest replica votes once; committed unchanged, so a committed  *)
        (* value keeps its quorum (its voter set only grows), Agreement holds. *)
        BY <1>1 DEF HonestVoteStep
  <1>2. CASE \E r \in Replicas, v \in Values : ByzVoteStep(r, v)
        BY <1>2 DEF ByzVoteStep
  <1>3. CASE \E v \in Values : CommitStep(v)
        (* the committed value has a quorum by the CommitStep guard; if two    *)
        (* values were committed, QuorumIntersect gives an honest replica in   *)
        (* both quorums, contradicting HonestVotesOnce.                        *)
        <2> SUFFICES ASSUME NEW w \in Values, CommitStep(w) PROVE IndInv'
              BY <1>3
        <2> QED BY QuorumIntersect DEF CommitStep
  <1>4. CASE UNCHANGED vars
        BY <1>4 DEF vars
  <1> QED BY <1>1, <1>2, <1>3, <1>4

(***************************************************************************)
(* Agreement holds in every reachable state, for every N = 3f+1.           *)
(***************************************************************************)
THEOREM Safety == Spec => []Agreement
PROOF
  <1>1. IndInv => Agreement BY DEF IndInv
  <1>2. Spec => []IndInv
        BY InitInv, NextInv, PTL DEF Spec
  <1> QED BY <1>1, <1>2, PTL
=============================================================================
