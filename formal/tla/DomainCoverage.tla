-------------------------- MODULE DomainCoverage --------------------------
(*
Certificate-formation integrity under a DOMAIN-STRUCTURED adversary.

The count-based result checks a scalar threshold f. That is the wrong adversary shape for the failure
mode this paper measures: prompt-injection approvals are correlated within a declared domain, so the
realistic adversary compromises whole domains rather than an arbitrary set of f signers.

Here the adversary structure A is exactly that: every set of signers obtained by taking the union of at
most T declared domains. The theorem is the one a coverage policy is supposed to give:

    \A Adv \in A : Adv cannot satisfy the certificate-coverage predicate.

Two configurations are checked, and the contrast is the point:
  MC_Coverage_OK    MinDomains = 3 > T = 2  -> invariant HOLDS   (coverage tolerates the adversary)
  MC_Coverage_Count MinDomains = 1 (count only)  -> invariant FAILS with a counterexample in which one
                    two-domain coalition forms a fully valid certificate.

Honest signers never approve the unsafe action, so any approval in `approvers` comes from a compromised
signer; the invariant therefore states that a compromised coalition alone cannot certify.
*)
EXTENDS Naturals, FiniteSets

CONSTANTS
    \* @type: Set(Str);
    Signers,
    \* @type: Str -> Str;
    DomOf,
    \* @type: Set(Str);
    Domains,
    \* @type: Int;
    Q,
    \* @type: Int;
    MinDomains,
    \* @type: Int;
    MaxPerDomain,
    \* @type: Int;
    T

VARIABLES
    \* @type: Set(Str);
    approvers,
    \* @type: Set(Str);
    compromised,
    \* @type: Bool;
    committed

vars == << approvers, compromised, committed >>

SignersOf(D) == { s \in Signers : DomOf[s] \in D }

\* the adversary structure: the union of at most T declared domains
AdversarySets == { SignersOf(D) : D \in { E \in SUBSET Domains : Cardinality(E) <= T } }

DomainsOf(A) == { DomOf[s] : s \in A }

CountIn(A, d) == Cardinality({ s \in A : DomOf[s] = d })

\* the certificate-formation predicate the gateway enforces
CertValid(A) ==
    /\ Cardinality(A) >= Q
    /\ Cardinality(DomainsOf(A)) >= MinDomains
    /\ \A d \in Domains : CountIn(A, d) <= MaxPerDomain

Init ==
    /\ compromised \in AdversarySets
    /\ approvers = {}
    /\ committed = FALSE

\* only a compromised signer approves the unsafe action; honest signers reject it
Approve ==
    /\ \E s \in compromised \ approvers :
         approvers' = approvers \cup {s}
    /\ UNCHANGED << compromised, committed >>

\* the gateway commits only on a valid certificate
Commit ==
    /\ ~committed
    /\ CertValid(approvers)
    /\ committed' = TRUE
    /\ UNCHANGED << approvers, compromised >>

\* Idle is admitted so that a terminal state in which no coalition can certify is not
\* reported as a deadlock; it is the intended outcome of the coverage policy.
Idle == UNCHANGED vars

Next == Approve \/ Commit \/ Idle

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------- properties

\* THEOREM (certificate-coverage integrity): no permitted fail-prone domain set satisfies the predicate.
CoverageInv == ~CertValid(approvers)

\* the safety consequence: an actuation the honest signers reject is never committed
NoUnsafeCommit == ~committed

\* sanity: the adversary really is the union of at most T domains
AdversaryWellFormed == Cardinality(DomainsOf(compromised)) <= T

=============================================================================
