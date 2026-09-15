-------------------------------- MODULE MC_N7 --------------------------------
\* N=7, f=2 instance (N = 3f+1, quorum 2f+1 = 5). Two Byzantine replicas (6,7).
EXTENDS BFTSafety
ConstInit ==
    /\ Replicas = {1,2,3,4,5,6,7}
    /\ Byzantine = {6,7}
    /\ F = 2
    /\ Values = {"a","b"}
=============================================================================
