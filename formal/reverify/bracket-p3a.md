# Phase 3a Task 3 — Claim A re-verification bracket (vote-semantics change)

The Phase-3a rewire changes the vote's CONTENT (honest vote = the agent's model judgment, not the OPA
decision) but does NOT change the certificate structure or the WellFormedQC predicate. Per the PI,
re-verify rather than assert; STOP (trigger a) if Claim A breaks.

## What changed vs what the proofs reason about
- Changed: `consensus/replica.py` (vote source = model judgment), `consensus/model_vote.py` (new),
  `consensus/integration.py` (post-quorum categorical floor). The vote is produced differently.
- Unchanged: `consensus/certificate.py` (`well_formed`, `well_formed_diverse` = WellFormedQC), the
  certificate object (2f+1 distinct valid ML-DSA votes for the same (actuation, view)), and both formal
  models (which reason about an abstract "a replica voted" and the cryptographic certificate, not how a
  vote was decided). So WellFormedQC is **unchanged** and the proofs are expected to hold verbatim.

## Bracket
| Property | Model | Pre-rewire | Post-rewire |
|----------|-------|-----------|-------------|
| J2 attribution (PQC) | `cert_attribution_pqc.spthy` | verified, forgery unreachable | **verified, forgery unreachable, 0 warn** |
| J2 attribution (diverse quorum) | `cert_attribution_pqc_diverse.spthy` | verified | **verified, 0 warn** |
| J2 contrast (classical/Shor) | `cert_attribution_classical.spthy` | falsified + forgery reachable | **falsified + forgery reachable, 0 warn** |
| J1 Agreement | Apalache `MC_N4` | NoError | **NoError** |
| J1 Integrity | Apalache `MC_N4` | NoError | **NoError** |

**Verdict: Claim A survives the vote-semantics change** (trigger a NOT fired). WellFormedQC is unchanged
and remains pinned across Apalache, Tamarin, and `consensus/certificate.py`. The attribution property is
implementation-independent of how a vote is decided, exactly as the composition note argued; what
changed is only what makes a vote *faulty* (a real injection now flips a real vote), which is a
Claim-B / evaluation question, not a Claim-A one.
