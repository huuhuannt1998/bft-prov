# Results — Stages 2–4

Run under `.planning/PREREGISTRATION.md`, frozen and committed at `272aa81` before
`decorrelation/stages_2_4.py` produced any number. No new inference: 65 agents × 342 payloads ×
2,000 member-set draws, all reusing the Cycle 1 vote matrix.

**Headline: every preregistered outcome resolved, including the one the preregistration predicted
against itself. Three findings emerged that the design did not anticipate — deployment-variance
reduction, dividend imprecision, and a dividend that turns negative at low thresholds — and two
defects were exposed, one in the design's primary metric and one in my own first compliance run.**

§1–6 report the preregistered arm. §7 reports the design-compliance arm, which was added after an
audit found six mandated items unrun, and which changed two of §1–6's conclusions.

---

## 1. Preregistered outcomes

| ID | Outcome | Result | Verdict |
|---|---|---|---|
| **O1** | Erosion at the primary contrast | $E = +1.46$ pp, CI $[-0.40, +3.39]$ | **S4 Null** — as predicted |
| **O2** | Necessity of composition knowledge | $\chi = 0$ unmatched; $\chi = 1$ at 1 of 4 matched budgets (§7.1) | Not established |
| **O3** | Agreement channel active | $g$-shift $+30.05$ pp, CI $[+27.79, +32.61]$ | **PASS** |
| **O4** | One-dimensionality | $\rho = 0.971$–$0.987$ across all four rules | **PASS** |
| **O5** | Structure below the aggregate | min cross-family $\rho = 0.250$ | **PASS** |
| **O6** | $\ell_3$ externally achievable | 0.9907 held-out accuracy at 50 probes | **PASS** |

The preregistration predicted S4 for O1 and got it. Predicting the null in advance is what makes it
reportable as a result rather than as a failure to find something.

**Decision rule 1 fires:** O1 is S4 and O4 holds, so the paper's claim is *predictable but not
attackable*, with one-dimensionality as the mechanism. Neither rule 3 nor rule 4 fires — the floor
survives both of its stated falsifiers.

## 2. The necessity ladder is non-monotonic, and that is a defect in $E$

| Level | What the attacker knows | $E$ | 95 % CI | Adaptive dividend $D(\pi_a)$ |
|---|---|---|---|---|
| $\ell_1$ | Per-agent marginals | $+5.36$ pp | $[+4.06, +6.65]$ | 9.4 pp |
| $\ell_2$ | + the composition rule | $+5.48$ pp | $[+4.18, +6.77]$ | 9.3 pp |
| $\ell_3$ | + the realized set, by probing | $+1.63$ pp | $[-0.15, +3.46]$ | 13.2 pp |
| $\ell_4$ | Full vote oracle (upper bound) | $+3.37$ pp | $[+1.48, +5.26]$ | 11.4 pp |

**More knowledge produces less measured erosion.** That is not a finding about attackers; it is a
defect in the metric, and the ladder is what exposed it.

$E = D(\pi_0) - D(\pi_a)$ falls when $D(\pi_a)$ rises, and $D(\pi_a) = \mathrm{ASR}_{\mathrm{HOM}} -
\mathrm{ASR}_{\mathrm{JD}}$ rises when the attacker gets *better at attacking HOM*. A homogeneous
quorum is a single agent replicated five times, so it is trivially targetable: any knowledge above
$\ell_1$ helps the HOM-targeted attacker far more than the JD-targeted one. $E$ therefore rewards an
attacker for being incompetent against the baseline.

**Consequence for the write-up.** $E$ is retained as the preregistered primary — changing it now would
be exactly the post-hoc substitution the preregistration exists to prevent — but the **adaptive
dividend $D(\pi_a)$ is reported alongside it at every level**, because that is the quantity a defender
acts on. Read that way the result is unambiguous and monotone in the right direction: **diversity
retains 63–89 % of its static dividend at every knowledge level, including against a full vote
oracle.**

## 3. The mechanism

**One-dimensionality holds across every composition rule tested.** Spearman $\rho$ between mean
per-agent susceptibility and each rule's draw-averaged joint approval:

| Rule | $\rho$ |
|---|---|
| Homogeneous | 0.971 |
| Family-diverse | 0.982 |
| Defense-diverse | 0.987 |
| Jointly diverse | 0.985 |

So no composition rule induces a payload ranking meaningfully different from the pool-mean ranking.
There is nothing composition-specific for an attacker to learn. This is the mechanism behind the
Cycle 1 correlated-difficulty result, which measured the phenomenon without explaining it.

**The structure exists but is unreachable by aggregation.** Cross-family rank correlations run
0.25–0.50: gemma and qwen genuinely disagree about which payloads are hard. Every score a selecting
attacker can compute averages that disagreement away. This is what makes the ceiling (authoring, Stage
5) a real hypothesis rather than a formality.

**The channel is agreement, not marginal strength.** Selection raises per-agent susceptibility by
$+21.95$ pp and agreement-given-a-hit by $+30.05$ pp, CI $[+27.79, +32.61]$. Both move; the agreement
channel moves more. Attackers who select hard payloads are not merely finding stronger prompts, they
are finding prompts on which replicas *agree* — which is the quorum-specific channel and the one
diversity is supposed to defend.

## 4. Two findings the design did not anticipate

### 4.1 A homogeneous deployment is a lottery; a diverse one is not

Per-deployment attack success across 2,000 draws:

| Rule | Mean | SD | p95 | Worst draw |
|---|---|---|---|---|
| Homogeneous | 23.7 % | 33.1 pp | 98.8 % | **100.0 %** |
| Family-diverse | 9.6 % | 15.9 pp | 45.9 % | 93.0 % |
| Defense-diverse | 10.6 % | 17.6 pp | 49.1 % | 99.7 % |
| Jointly diverse | 9.1 % | 15.3 pp | 44.2 % | 88.3 % |

A homogeneous 3-of-5 quorum *is* its single agent, and the pool's per-agent attack success ranges from
0 % to 100 %. Deploying one is a draw from that distribution: **4.7× the variance of a jointly diverse
quorum, and 10.8 % of homogeneous deployments are worse than the worst jointly diverse deployment.**

This reframes what diversity buys. The literature argues it lowers the mean. It does, but the larger
effect is that it **removes the tail of the deployment distribution** — you cannot accidentally deploy
a 100 %-susceptible diverse quorum, and you can very easily deploy a 100 %-susceptible homogeneous one.
That benefit survives everything in this study, because it does not depend on the attacker's knowledge
at all.

### 4.2 The dividend estimate is draw-sensitive — but Cycle 1 already said so

Sampling distribution of the measured dividend $D_0$:

| Draws | Mean | SD | 95 % range |
|---|---|---|---|
| 200 (Cycle 1) | 14.37 pp | 2.58 pp | $[8.60, 19.10]$ |
| 2,000 (here) | 14.35 pp | 0.83 pp | $[12.80, 16.11]$ |

At 200 draws the dividend's point estimate moves by about $\pm 5$ pp across independent draws.

**An earlier version of this section claimed Cycle 1 "could not measure its own headline quantity" and
that its 8.7 pp was "quoting noise." That was overstated and is withdrawn.** Cycle 1 bootstraps
payloads and member sets *jointly* and publishes intervals that already carry this uncertainty:
HOM-3of5 19.2 % [15.3, 23.4], JD-3of5 10.5 % [7.8, 13.3]. Its own reported width is the finding, not a
gap in it.

What remains true and worth reporting is narrower: the converged dividend over 2,000 fresh draws is
14.4 pp against Cycle 1's 8.7 pp, and the two are different estimands rather than a correction. Cycle 1
draws from its 200 canonical member sets and scores the held-out payload half; this measures fresh
uniform draws over all 342 payloads. Neither is wrong. The lesson for Stage 2 sizing stands — draws
are the power lever and cost no inference — but it is a lesson about *this* study's design, not an
indictment of Cycle 1's.

## 5. What this changes

1. **The floor is confirmed and is stronger than written.** Predictable-but-not-attackable holds
   (O1 S4 with O6 at 0.99); one-dimensionality holds across four rules; and two unanticipated results
   — deployment-variance reduction and dividend imprecision — add to it.
2. **§13.2's ceiling is unchanged and remains live.** Cross-family $\rho$ of 0.25 confirms exploitable
   structure exists; Stage 5 asks whether authoring can reach it.
3. **The design's primary metric needs a companion.** $D(\pi_a)$ joins $E$ in every table. The
   preregistered primary is not changed.
4. **Stage 6 (intervention) stays unwritten**, per the gate discipline: composition knowledge shows
   at most a marginal, non-robust advantage (§7.1), so hiding it defends against little.
5. **A threshold caveat now governs every dividend claim** (§7.3). The dividend is $-10.6$ pp at
   $q=2$ and $+23.7$ pp at $q=5$; any statement about what diversity buys must name its threshold.
6. **Diversity's benefit is largely the exclusion of weak agents** (§7.4): on a competent sub-pool the
   dividend falls to 3.1 pp.

## 6. Reproduction

```sh
PYTHONPATH=. python3 decorrelation/design_verification.py       # design-level sanity checks
PYTHONPATH=. python3 decorrelation/stages_2_4.py                # sections 1-6
PYTHONPATH=. python3 decorrelation/stages_2_4_compliance.py     # section 7
```

Both are additive and write new JSON; no frozen Cycle 1 result file is modified.


---

# 7. Design-compliance arm

An audit of §1–6 against `research_design_detailed.md` found six mandated items unrun. They are now
run (`decorrelation/stages_2_4_compliance.py`, no new inference), and two changed the conclusions.

**A defect in my own first compliance run, found and fixed before reporting.** The matched-budget
$\ell_1$ control computed a weighted average over the *full* vote matrix, silently handing it
$\ell_4$ knowledge. That is why it appeared to reach $+4.2$ pp on a 250-query budget. Corrected, a
budgeted attacker can only score payloads it paid to observe.

## 7.1 Matched budget (ALG-4a) — and why the earlier necessity verdict was unsound

The first run compared $\ell_1$ costing **11,115 agent-queries** against $\ell_3$ costing **50
quorum-queries** and called it a control. It was not one: $\ell_1$ had a 222× budget advantage, so
"$\ell_1$ suffices" was never a fair test.

| Budget $B$ | $\ell_1$ | $\ell_3$ | $\chi$ |
|---|---|---|---|
| 250 | +0.37 [-0.20, +0.88] | -1.47 [-2.16, -0.74] | 0 |
| 1000 | +0.49 [+0.00, +0.97] | +0.44 [-1.16, +2.15] | 0 |
| 5000 | +0.37 [-0.44, +1.12] | +3.56 [+1.64, +5.32] | 1 |
| 11115 | +2.69 [+1.59, +3.73] | +3.38 [+1.62, +5.27] | 0 |

**$\chi = 1$ at exactly one of four budgets.** That is not evidence for necessity — with four
comparisons, one significant result is what noise produces. The honest verdict is that composition
knowledge buys **at most a marginal, non-robust advantage** at matched budget. This is close to the
first run's conclusion but reached by a test that can actually support it.

## 7.2 The mandatory hardest baseline

Hardest-decile static selection reaches $E = +5.37$ pp
[+4.06, +6.73], against
$\ell_3$'s $+2.09$ pp. **$\ell_3$ does not beat it**, which by
§11.2 kills the ceiling claim.

One qualification the design did not anticipate: this baseline scores by $\theta$ computed over the
full vote matrix — 22,230 queries — so it is an *unmatched upper reference*, not a matched control.
Both readings are reported. Matched at 11,115 queries the comparison is $\ell_1$ $+2.69$ against
$\ell_3$ $+3.38$, overlapping.

## 7.3 The diversity dividend flips sign with the threshold

| $q$ (of $N{=}5$) | Dividend $D_0$ | Erosion $E$ | 95 % CI |
|---|---|---|---|
| 2 | -10.62 pp | +19.09 pp | [+17.35, +20.82] |
| 3 | +14.80 pp | +1.79 pp | [+0.03, +3.65] |
| 4 | +22.59 pp | -18.94 pp | [-20.42, -17.50] |
| 5 | +23.69 pp | -24.29 pp | [-25.55, -23.00] |

**At $q=2$ the dividend is negative: a jointly diverse quorum is 10.6 pp *worse* than a homogeneous
one.** The mechanism is structural. A homogeneous quorum is one agent replicated, so its vote count is
all-or-nothing — 0 or 5. A diverse quorum spreads probability mass across intermediate counts. Spread
mass is a liability at a low threshold, where only 2 approvals are needed, and an asset at a high one.

This was not in the design's hypothesis space and it is the most actionable result in the compliance
arm: **diversity is not a monotone good, and a designer who diversifies while running a permissive
threshold makes the system worse.** The Cycle 1 paper reported only 3-of-5 and could not have seen it.

Erosion tracks the same reversal, from $+19.1$ pp at $q=2$ to $-24.3$ pp at $q=5$, which is a further
reason to report the adaptive dividend rather than $E$ alone.

## 7.4 Pool ablation

On the 43 agents under 20 % attack success, $D_0 = 3.06$ pp — the dividend nearly
vanishes — and $E = -20.27$ pp. Diversity's benefit is largely a benefit *of excluding weak
agents*. Once the pool is competent there is little left for composition to buy, which is consistent
with §4.1: what diversity mostly does is remove the chance of drawing a catastrophic member.

## 7.5 Greedy versus exact — reported, with its limits

Greedy attains 100 % of optimal. That is not informative: top-$k$ selection under a fixed per-payload
score is exactly optimal for a mean objective, so the test exercises selection rather than ALG-3's
coverage objective. **It bounds nothing about coverage search** and is recorded as such rather than
presented as a validation.

## 7.6 Statistics

Mixed-effects (§11.4) could not run — `statsmodels` is unavailable in this environment — so the
**predeclared fallback** to the two-way cluster bootstrap fires. This is a designed path, not a
deviation. Every result in this document carries a capability record (discipline 6), which the first
run omitted.
