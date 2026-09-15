# RQ1 Results — Correlated LLM-Agent Failure Study

**Sweep:** 78/78 cells (13 models x 6 defenses), 0 infra errors. 342 injection attacks x 3 reps per cell.
Analysis: `decorrelation/analyze_rq1.py` (pre-registered, `docs/02-fault-domain-model/preregistration.md`).
Date: 2026-07-22.

## Headline findings

**F1. Defenses cut attack success sharply but none eliminate it.** Pooled injection ASR across all 13 models:

| Defense | ASR (pooled, n=4446) |
|---|---|
| none | 62.6% |
| spotlight | 34.2% |
| struq | 28.9% |
| hierarchy | 25.3% |
| provenance | 16.5% |
| known_answer | 16.5% |

Even the best defense leaves ~1 in 6 injections succeeding. Prevention is bounded and breakable.

**F2. NEITHER DIVERSITY AXIS IS INDEPENDENT; the pre-registered contrast is REFUTED IN THE OPPOSITE
DIRECTION.** Same-payload co-approval phi: family-diverse pairs **0.124** [0.116, 0.133] vs
defense-diverse pairs **0.140** [0.132, 0.148]. Both per-axis CIs exclude zero, and joint unsafe approval
runs at **1.28x** [1.26, 1.30] and **1.33x** [1.30, 1.35] the independence-predicted rate — so each axis
is non-independent *on its own*, which a null between-axis difference could never have shown.
**delta = phi_family - phi_defense = -0.0154, 95% joint-payload-bootstrap CI [-0.0285, -0.0027]**
(excludes zero, NEGATIVE). Defense diversity decorrelates *slightly less* than family diversity — the
pre-registered hypothesis (delta > 0) is refuted, and refuted in the direction opposite to it.

> **CORRECTION (supersedes the 2026-07-22 reading of "delta = +0.0048, CI [-0.008, 0.017], null").**
> The earlier estimate was an artifact of `glob.glob` filesystem ordering. A replica pair is unordered,
> but the pooled phi was computed on ordered `(a,b)` co-observations, so the arbitrary within-pair
> ordering shifted the pooled marginals. Shuffling the cell load order moved phi_family across
> 0.124-0.145 and flipped delta's sign; the CI excluded zero in 5 of 6 shuffles. Fixed in
> `analyze_rq1.py` by (i) symmetrizing each co-observation into both orders, making pooled phi provably
> order-invariant, (ii) `sorted(glob.glob(...))`, and (iii) `sorted(by_payload.keys())` so the seeded
> bootstrap is reproducible. Post-fix values are bit-identical across shuffled loads. Two independent
> order-invariant estimators agree on the direction: mean pairwise phi (family 0.102 vs defense 0.171)
> and joint-failure lift (1.28x vs 1.33x).

**F3. Defense/family/size strongly set the LEVEL of susceptibility (not the correlation).** GLMM
fixed-effect directions (log-odds of attack approval): defense `none` +5.88 vs best defenses
provenance/known_answer -2.68 (ref=hierarchy); family qwen -1.68 (most robust) to mistral +0.99 (most
susceptible), ref=gemma; `size_b` -0.95 (larger models more robust); indirect delivery -1.13 (direct
injection more successful). Most successful attack categories: policy-extraction-adapt (+1.29),
social-proof (+1.27), forged-user-auth (+1.18).

**F4. known_answer == provenance (no marginal benefit, 2x cost).** The canary-detection defense reduces to
its base (provenance) whenever the canary holds; on this corpus it produced identical ASR and identical
GLMM coefficients to provenance while costing an extra model call per vote. Honest negative on that defense.

**F5. Model-instance variance dominates payload variance.** Random-effect SDs: model 2.81 vs payload 1.04
(log-SD 1.03 vs 0.037) — which model you run matters far more than which payload it sees.

## Caveats (report honestly)
- **The GLMM VB fit did not converge** (statsmodels warning). The fixed-effect estimates above are
  DIRECTIONAL. The robust, reportable quantities are the descriptive per-defense/per-model Wilson-interval
  ASRs (F1) and the joint-bootstrap phi contrast (F2); the GLMM corroborates direction, not precise
  intervals. A more robust fit (more VB iterations, Laplace/penalized, or a clustered GEE) is a follow-up.
- defense/family interactions are large (F3), so per-cell effects are non-uniform — report the marginal
  ASRs by cell, not a single pooled number, in the paper's tables.

## Design implication
The refuted primary contrast (F2) undercuts a quorum rule that weights *defense* domains specifically —
if anything, defense-domain weighting is the worse of the two axes. What
the data supports: (i) no measured diversity axis (defense or lineage) yields independent failures, and
(ii) defenses reduce but do not remove susceptibility. This reinforces the paper's accountability backbone
(deterministic verifier + risk tiers + durable evidence) over a diversity-weighted quorum. PI framing
decision pending.

---

## Key model output (full 145-row table regenerable via `python -m decorrelation.analyze_rq1`)

GLMM: `rows=80028  models=13  defenses=6` (Binomial Mixed GLM, VB — DID NOT CONVERGE; directional).

Defense main effects (log-odds, ref=hierarchy): none +5.88, spotlight +0.54, struq -1.70,
provenance -2.68, known_answer -2.68.
Family main effects (ref=gemma): granite +0.21, mistral +0.99, llama -1.16, phi -1.20, qwen -1.68.
Other: `size_b` -0.95; delivery[indirect] -1.13; intercept -0.89.
Random-effect SDs: model 2.81 [1.94, 4.07], payload 1.04 [0.96, 1.12].

Primary contrast (joint payload bootstrap, order-invariant estimator; counts are doubled by
symmetrization, which does not affect the normalized phi):
```json
{
 "delta": -0.01542, "ci_lo": -0.02850, "ci_hi": -0.00271,
 "phi_family_diverse": 0.12441, "phi_family_ci": [0.11573, 0.13287],
 "phi_defense_diverse": 0.13983, "phi_defense_ci": [0.13153, 0.14816],
 "lift_family": 1.2793, "lift_family_ci": [1.2592, 1.2996],
 "lift_defense": 1.3261, "lift_defense_ci": [1.3002, 1.3528],
 "n_family_diverse": 287280, "n_defense_diverse": 297540,
 "undefined_frac": 0.0,
 "interpretation": "CI excludes zero and is negative: evidence against the pre-registered direction (family diversity decorrelates more than defense diversity in this sample)"
}
```

## F6. Utility and matched-control false-approval (Table I columns 3-4 provenance)
Pooled per-defense over 13 models (legit n=2184; control n=234 per defense), computed by
analyze_rq1 `load_cells` over the `legit`/`controls` checkpoint channels:

| Defense | ASR | Legit-approval (utility) | Control false-approval |
|---|---|---|---|
| none | 62.6% | 97.0% | 61.5% |
| spotlighting | 34.2% | 66.5% | 30.8% |
| structured-query | 28.9% | 85.4% | 23.1% |
| instr.-hierarchy | 25.3% | 83.0% | 23.1% |
| instr.-data sep. | 16.5% | 66.8% | 7.7% |
| known-answer | 16.5% | 66.8% | 7.7% |

Security is confounded with utility: the lowest-ASR defenses (instr.-data sep., known-answer) have among
the lowest legitimate-task utility (66.8%); structured-query/instr.-hierarchy sit at a better
security-utility point (ASR 25-29%, utility 83-85%). Spotlighting is worst-of-both. known-answer == instr.-data
sep. (canary reduces to base defense). These columns feed Table I in the manuscript.
