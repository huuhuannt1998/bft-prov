# Phase 2 Task 4 — Tamarin certificate-attribution results (J2)

Tamarin 1.12.0, Apple M4. Core case **N=4, f=1, quorum=3**; quantum adversary (ML-DSA retained)
controlling one Byzantine agent (key leaked). Vocabulary per `docs/p2-01-joint-property/`.

| Lemma | `cert_attribution_pqc.spthy` | `cert_attribution_classical.spthy` |
|-------|------------------------------|------------------------------------|
| `actuation_reachable` (exists) | verified (12) | verified (12) |
| `J2_honest_quorum_backing` (all) — every actuation backed by ≥2 distinct-key honest votes | **verified (32)** | **falsified — Shor forges cert (13)** |
| `J2_injective` (all) — no cert replay | verified (2) | verified (2) |
| forgery (no honest backing) | **unreachable** | `forgery_reachable_classical`: **verified (16)** |

0 wellformedness warnings on both; ≤0.5 s each.

## Result
The Phase-1 single-signature contrast lifts to the **quorum certificate**: with ML-DSA the certificate
requires ≥ f+1 = 2 genuine honest votes (no f-bounded Byzantine set can forge or re-attribute it); with
classical signatures Shor recovers all keys and the certificate is forgeable. This is the J2 core. The
certificate-BUFF analysis (mix-and-match / set-substitution / cross-view replay) is in
`docs/p2-04-cert-buff/`.

## Two modeling pitfalls fixed (recorded for the composition/interface discipline)
1. **Unbounded Byzantine registration** — the first model let the adversary register f≫1 Byzantine
   agents and forge a full certificate (J2 falsified, forgery reachable). Fixed with
   `AtMostOneByzantine` (and the 2-arg arity fix the wellformedness lint caught — the restriction was
   silently vacuous until the action-fact arity matched).
2. **Name-vs-key attribution** — keying the honest-quorum lemma on reusable agent *names* let one name
   cover two keys, spuriously failing J2. Attribution is **per public key**; `HonestVote` now records
   the voting key and the lemma requires distinct keys. (Same class of error as the Phase-1 EO lemma —
   the right granularity is the cryptographic key, not the PKI name.)
