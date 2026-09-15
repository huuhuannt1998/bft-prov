-------------------------------- MODULE MC_Div_Deadlock --------------------------------
EXTENDS BFTSafetyDiverse
ConstInit ==
    /\ Replicas = {1,2,3,4}
    /\ Byzantine = {4}
    /\ F = 1
    /\ Values = {"a","b"}
    /\ Family = [r \in {1,2,3,4} |-> IF r \in {1,2} THEN "llama" ELSE "qwen"]
    /\ MinFamilies = 3
    /\ CapPerFamily = 1
=============================================================================
