# Scope and Claims — the two claims, never merged

Pinned per PI gate resolution `dec_01KVX5MB9JB7EWE06YYGV7290M` (Phase 2, option 2). The writeup MUST
state these as two distinct claims, one sentence each, and never merge them.

## Claim A — the verified joint property (UNCONDITIONAL)
PQ-BFT-Prov machine-checks a joint property: for every committed actuation, a single post-quantum
quorum certificate is simultaneously the **BFT-safety witness** (Apalache: Agreement + Integrity, J1,
at N=4/f=1 and N=7/f=2) and the **non-repudiable quantum-attribution token** (Tamarin: injective
attribution-binding over the certificate, J2, holds for ML-DSA / Shor-forgeable classically),
composed via the shared `WellFormedQC` interface. **This claim holds unconditionally** — it does not
depend on any empirical decorrelation assumption.

## Claim B — deployed end-to-end safety (CONDITIONAL)
The deployed system blocks unsafe actuation **conditional on ≤ f agents being faulty**, i.e. on
indirect-injection cross-family transfer staying **below quorum**. Measurement (Task 6, 4 families ×
12 smart-home injections) shows this holds for 10/12 injections but **fails for 2/12** that transfer to
≥ 2f+1 families (`lock-5` flips all four). So Claim B is **bounded**: safe against sub-quorum-transfer
injections; **not** safe against the strongest universally-transferring payloads without
correlation-aware quorum sizing / input sanitization / more-robust families.

## Honesty riders (state verbatim)
- Actuation is **emulated** (M4-only Home Assistant virtual devices); M4 timing is "feasibility on a
  capable hub," never a constrained-device measurement; no physical-actuation claim.
- "First verified realization + systematization," **not** a conceptual first: quorum-gated actuation,
  the correlated-fault observation, and the symbolic quantum-adversary device are prior art (deVadoss
  arXiv:2504.14668) — cited, not claimed. We **measure** correlated faults where deVadoss observed them.
- Decorrelation empirical limits: 12 injections, static (non-optimized) payloads, 4 families, one model
  each, single-turn. **Direction robust, exact rates not.**
- Primitives (ML-DSA/ML-KEM) assumed from verified implementations (liboqs/Formosa-Crypto), not
  re-proven. Certificate-BUFF GO rests on the aggregate (not threshold) structure — the 2025/427
  threshold-robustness caveat is parked on the deferred threshold-ML-DSA stretch goal.
- Methodology scar (jrn_01KVX5MKYDSWAQT2SVPZ330P92): the recurring machine-checked-attribution pitfall
  is conflating identity-layer artifacts with cryptographic ownership; caught three times; surfaced.
