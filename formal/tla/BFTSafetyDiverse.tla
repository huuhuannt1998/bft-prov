--------------------------- MODULE BFTSafetyDiverse ---------------------------
\* Correlation-aware variant (mis_01KVX5PTHHMVTB4M5E94RZ80P3): the quorum must span >= MinFamilies
\* distinct model families (and no family exceeds CapPerFamily). This is a STRICTLY STRONGER commit
\* condition than BFTSafety, so safety (Agreement/Integrity) is preserved; the new risk is LIVENESS
\* (a diverse quorum may be UNSATISFIABLE if too few families are available) — checked explicitly.
EXTENDS Integers, FiniteSets

CONSTANTS
    \* @type: Set(Int);
    Replicas,
    \* @type: Set(Int);
    Byzantine,
    \* @type: Int;
    F,
    \* @type: Set(Str);
    Values,
    \* @type: Int -> Str;
    Family,
    \* @type: Int;
    MinFamilies,
    \* @type: Int;
    CapPerFamily

VARIABLES
    \* @type: Int -> Set(Str);
    votes,
    \* @type: Set(Str);
    committed

Honest == Replicas \ Byzantine
QuorumSize == (2 * F) + 1

\* @type: (Str) => Set(Int);
Voters(v) == { r \in Replicas : v \in votes[r] }
\* @type: (Str) => Set(Str);
VoterFamilies(v) == { Family[r] : r \in Voters(v) }
\* @type: (Str, Str) => Int;
FamilyCount(v, fam) == Cardinality({ r \in Voters(v) : Family[r] = fam })

\* Correlation-aware quorum: size >= 2f+1, spans >= MinFamilies families, no family over the cap.
HasDiverseQuorum(v) ==
    /\ Cardinality(Voters(v)) >= QuorumSize
    /\ Cardinality(VoterFamilies(v)) >= MinFamilies
    /\ \A fam \in VoterFamilies(v) : FamilyCount(v, fam) <= CapPerFamily

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
    /\ HasDiverseQuorum(v)
    /\ committed' = committed \cup {v}
    /\ UNCHANGED votes

Next ==
    \/ \E r \in Replicas, v \in Values : HonestVoteStep(r, v)
    \/ \E r \in Replicas, v \in Values : ByzVoteStep(r, v)
    \/ \E v \in Values : CommitStep(v)

\* SAFETY (preserved under the stronger commit condition).
Agreement == Cardinality(committed) <= 1
Integrity == \A v \in committed :
    Cardinality({ r \in Honest : v \in votes[r] }) >= (F + 1)

\* LIVENESS probe: if this invariant is VIOLATED, a diverse quorum CAN commit (liveness OK);
\* if it HOLDS (never violated), the diverse quorum is UNSATISFIABLE -> silent unable-to-act.
DiverseNoCommit == committed = {}
==============================================================================
