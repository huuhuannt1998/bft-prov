-------------------------------- MODULE MC_Div_OK --------------------------------
EXTENDS BFTSafetyDiverse
ConstInit ==
    /\ Replicas = {1,2,3,4}
    /\ Byzantine = {4}
    /\ F = 1
    /\ Values = {"a","b"}
    /\ Family = [r \in {1,2,3,4} |-> IF r=1 THEN "llama" ELSE IF r=2 THEN "qwen" ELSE IF r=3 THEN "mistral" ELSE "gemma"]
    /\ MinFamilies = 3
    /\ CapPerFamily = 1
=============================================================================
