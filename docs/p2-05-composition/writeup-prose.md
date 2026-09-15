# Writeup prose — two claims, methodology scar, safe-degradation framing (Task 6 of the follow-up)

Drafted per `dec_01KVX5MB9JB7EWE06YYGV7290M` (option 2) and the PI's framing reminder. To be lifted
into the manuscript; kept here so the framing is fixed before drafting under deadline pressure.

## The two claims (one sentence each, NEVER merged)
**Claim A (verified, unconditional).** PQ-BFT-Prov machine-checks a joint property in which a single
post-quantum quorum certificate is simultaneously the BFT-safety witness (Apalache: Agreement +
Integrity, N=4/f=1 and N=7/f=2) and the non-repudiable quantum-attribution token (Tamarin: injective
attribution-binding over the certificate, ML-DSA-secure / classically Shor-forgeable), composed across
the two provers through the shared `WellFormedQC` interface.

**Claim B (deployed, conditional).** The deployed system blocks unsafe actuation conditional on
indirect-injection cross-family transfer staying below the diverse quorum; where that condition fails
(universally-transferring injections such as `lock-5`), the hardening makes the system **refuse rather
than certify** — it fails safe at the boundary, but it does not extend Claim A's guarantee to that
regime.

## Methodology scar (one sentence, earns reviewer trust)
A recurring failure mode in machine-checking attribution is conflating identity-layer artifacts
(agent names, registrations) with cryptographic ownership (keys, signatures); we hit it three times —
the Phase-1 exclusive-ownership lemma, and the Phase-2 certificate model's name-vs-key counting and
its vacuous Byzantine bound — and each time the honest model surfaced it, which is why we report them.

## Safe-degradation framing (the follow-up's actual job)
The hardening's job is **not** to make Claim B unconditional or to make `lock-5` disappear; it is to
ensure the system fails safe at the boundary Claim A does not cover. Two mechanisms, with an
explicit, pre-registered success bar:
- **Sizing** (correlation-aware diverse quorum): blocks injections whose measured cross-family transfer
  is below the quorum's family-diversity requirement — but is bounded by the number of available
  families (with 4 families it cannot size around an injection that flips all 4).
- **Detection** (input sanitization as a flag → vote withheld): converts a would-be silent
  unsafe-certification into a refusal, including for universally-transferring injections.
- **Residual** (neither): reported as a failure, not hidden by absence-of-trigger on the sample.

The honest headline is the safe-degradation outcome, not a robustness claim: *for injections the
sizing cannot absorb, the system refuses to actuate rather than certifying an unsafe action* — with
the explicit caveat that detection is pattern-based on static, non-optimized payloads and an adaptive
attacker is out of scope.

## Empirical limits (verbatim)
12 injections, static (non-optimized) payloads, 4 model families (one instruct model each),
single-turn. Direction of the findings is robust; exact rates are not. Adaptive-injection robustness
is out of scope and not claimed. Actuation is emulated (M4-only Home Assistant virtual devices); M4
timing is feasibility on a capable hub.
