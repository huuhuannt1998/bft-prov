-------------------------------- MODULE MC_N4 --------------------------------
\* N=4, f=1 instance (N = 3f+1, quorum 2f+1 = 3). One Byzantine replica (id 4).
EXTENDS BFTSafety

ConstInit ==
    /\ Replicas = {1, 2, 3, 4}
    /\ Byzantine = {4}
    /\ F = 1
    /\ Values = {"a", "b"}
=============================================================================
