# Task 2 — Signature-based BFT consensus + ML-DSA quorum certificate

Reference implementation of the Phase-2 fusion point: a signature-based BFT round whose **aggregate
quorum certificate** is the single artifact serving as both BFT-safety witness and post-quantum
attribution token. Normative spec: `docs/p2-01-joint-property/joint-property-spec.md`.

## Protocol (PBFT/HotStuff normal-case path, single-actuation decision)
1. **Propose** — a leader proposes `(actuation a, view v)`.
2. **Vote** — each replica casts an **ML-DSA-signed** vote `Sign(sk_i, ⟨pk_i, a, v, decision⟩)`.
   Honest replicas vote `approve` iff the **OPA/Rego guard** permits `a` (the LLM is untrusted; the
   guard decides the vote). Byzantine replicas (≤ f) may rubber-stamp, equivocate, or stay silent.
3. **Certify** — any replica collecting **2f+1 distinct, authentic, valid approve-votes** for the same
   `(a, v)` forms the **quorum certificate `QC`** (`consensus/certificate.py:well_formed` = the shared
   `WellFormedQC` interface).
4. **Actuate** — `QC` feeds the Phase-1 provenance chain + OPA gate → emulated actuation
   (`consensus/integration.py`). The actuation binds to `QC`, not to any single signature.

## Why signature-based (the fusion point, not stapled)
The certificate is an **aggregate of individual ML-DSA signatures**, so it *is* the attribution token:
removing the signatures (signature-free BFT) would decouple PQC from BFT. Threshold ML-DSA (a single
compact certificate) is a **stretch goal**, not Phase-2 core (dec_01KVWZ2RY2TDP7BQCPSKETY3RN).

## Per-vote BUFF binding (seed for Task 4)
Each vote binds `⟨pk_i, a, v, decision⟩` — the per-agent lift of the Phase-1 pk-binding transform
(`attribution_buff_fixed.spthy`). `well_formed` enforces same-`(a,v)` and distinct `pk_i`, which is
what closes certificate-level **mix-and-match**, **agent-set substitution**, and **cross-view replay**
— the certificate-BUFF properties Task 4 machine-checks (mindful of the threshold-EO caveat, 2025/427).

## Demonstrated (run: `PYTHONPATH=. python3 -m consensus.consensus`)
| Case | Setup | Result |
|------|-------|--------|
| A | safe actuation, all honest (N=4,f=1) | approve 4/3 → **certified** |
| B | **unsafe** (unlock, unauthorized) + 1 Byzantine rubber-stamp | approve 1/3 → **blocked** (the safety property: f alone < 2f+1) |
| C | safe + 1 equivocator | equivocation absorbed by distinctness → certified |
| D | hazardous but **authorized** | honest agents approve → certified |

Case B is the runtime witness of J1-Integrity (Apalache discharges it formally in Task 3): with ≤ f
Byzantine, a certificate needs ≥ f+1 honest votes, so an actuation the honest majority rejects cannot
be certified. **Scope:** this is the normal-case safety path; view-change/liveness (partial synchrony)
is noted in the spec and not part of the safety core. Files: `vote.py`, `certificate.py`,
`replica.py`, `consensus.py`, `integration.py`.
