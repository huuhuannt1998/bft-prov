# Re-verification bracket — J1/J2 baseline vs post-change (mis_01KVX5PTHHMVTB4M5E94RZ80P3)

PI refinement #1: re-verify the verified core BEFORE any `WellFormedQC` change (baseline) and AFTER
the quorum-rule change, so any break is attributable. Sanitization sits in front of the vote and must
be confirmed not to touch certificate structure (→ needs no re-verification).

## BASELINE (current WellFormedQC, before correlation-aware change)
| Property | Model | Result |
|----------|-------|--------|
| J2 attribution | `cert_attribution_pqc.spthy` | `J2_honest_quorum_backing` **verified (32)**, `J2_injective` verified, forgery unreachable, **0 warnings** |
| J1 Agreement | Apalache `MC_N4` | **NoError** |
| J1 Integrity | Apalache `MC_N4` | **NoError** |

## POST-CHANGE (family-diversity quorum rule added to WellFormedQC)
The quorum-rule change = require the certificate's votes to span ≥ MinFamilies distinct families,
no family over a cap (`consensus/certificate.py:well_formed_diverse`; Tamarin family-distinctness;
Apalache `HasDiverseQuorum`). A strictly STRONGER commit condition.

| Property | Model | Result |
|----------|-------|--------|
| J2 attribution | `cert_attribution_pqc_diverse.spthy` | `J2_honest_quorum_backing` **verified (44)**, `J2_injective` verified, forgery unreachable, **0 warnings** |
| J1 Agreement | Apalache `MC_Div_OK` (4 families, MinFamilies=3, f=1) | **NoError** (safety preserved) |
| J1 Integrity | Apalache `MC_Div_OK` | **NoError** |
| **Liveness (live)** | Apalache `MC_Div_OK`, `DiverseNoCommit` | **violated** → a diverse quorum CAN commit under f=1 → **liveness OK** |
| **Liveness (deadlock demo)** | Apalache `MC_Div_Deadlock` (only 2 families, MinFamilies=3) | `DiverseNoCommit` **holds** → diverse quorum NEVER forms → **silent unable-to-act** |

**Bracket verdict: the verified core SURVIVES the WellFormedQC change** (J1 + J2 both still hold) —
checkpoint trigger (d) NOT fired. The diversity rule preserves safety; its cost is **liveness**, which
is satisfiable iff enough distinct families are provisioned (≥ MinFamilies available-and-honest).

**Safety-vs-liveness choice (PI refinement #2):** when they conflict (too few families to meet
MinFamilies), we choose **liveness** for life-safety-critical actuations (a door must be able to unlock
in an emergency) by REQUIRING the deployment to provision `available_families ≥ MinFamilies + f` so the
diverse quorum is always reachable; if that provisioning cannot be met, the system must **fail to a
declared default** (refuse-and-alert) rather than silently deadlock. Stated, not left implicit.

**Sanitization placement (PI refinement #1):** the sanitization/detector stage (Task 2) operates on
each agent's *ingested content before it votes*; it does **not** touch the certificate structure,
`WellFormedQC`, or any signed field — so it requires **no** re-verification of J1/J2. Confirmed by
construction (`decorrelation/sanitization.py` transforms vote *inputs*, never the vote/cert objects).
