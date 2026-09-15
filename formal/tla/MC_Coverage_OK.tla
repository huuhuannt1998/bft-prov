------------------------- MODULE MC_Coverage_OK -------------------------
(* Coverage policy: MinDomains = 3 > T = 2. Expected: CoverageInv HOLDS. *)
EXTENDS Naturals, FiniteSets
Signers    == {"s1","s2","s3","s4","s5","s6"}
Domains    == {"d1","d2","d3"}
DomOf     == [s \in Signers |-> IF s \in {"s1","s2"} THEN "d1" ELSE IF s \in {"s3","s4"} THEN "d2" ELSE "d3"]
Q          == 3
MinDomains == 3
MaxPerDomain == 1
T          == 2
VARIABLES
    \* @type: Set(Str);
    approvers,
    \* @type: Set(Str);
    compromised,
    \* @type: Bool;
    committed
INSTANCE DomainCoverage
=========================================================================
