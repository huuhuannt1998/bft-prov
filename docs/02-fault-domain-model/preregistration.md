# RQ1 Pre-registration — Correlated-Failure Study (PQ-BFT-Prov, TDSC redesign)

**Status:** Phase 0 canonical reference, frozen before any RQ1 result is read. `decorrelation/analyze_rq1.py`
(Phase 1) must conform to this document; every RQ1 table in the manuscript cites its "pre-registered" status
against this document, not against a plan written after seeing the data.

**Source of truth:** this document operationalizes `docs/superpowers/specs/2026-07-17-tdsc-fault-domain-redesign-design.md`
§7 (RQ1) and reuses the domain taxonomy and terminology fixed in the sibling document
`docs/02-fault-domain-model/threat-model.md` (`lineage`/`family`, `size`, `defense`, `quantization/runtime`,
`isolation/key-domain`; adversary A, the content attacker, is the adversary this study measures). Where this
document and the design spec could be read to disagree, the design spec is authoritative for what is
instantiable on this testbed, and this document is authoritative for the frozen analysis plan and stopping
rule.

---

## 1. Research question (RQ1)

**Does defense diversity decorrelate LLM-agent injection failure more than model-family diversity?**

Concretely: when a quorum of agent replicas votes on whether to approve an actuation, is the probability
that two replicas fail together (both approve a successful injection on the same payload) lower when the
two replicas differ in **defense mechanism** than when they differ only in **model family**? This is the
"decisive experiment" of design spec §7 — its output defines the fault-domain-aware quorum policy's
domain-coverage parameters (design spec §5.3) built in later phases. RQ1 does not evaluate the quorum
policy itself (that is RQ2); it measures the raw correlation structure of injection failure across the
`defense` and `lineage`/`family` fault domains fixed in `threat-model.md` §1, so that structure can be used
to choose which domains the quorum-coverage rule should weight.

RQ1 measures adversary **A (content attacker)** from `threat-model.md` §2: an attacker who controls
untrusted content (calendar, email, document, notification, web, or retrieval content) and attempts to
manipulate the agent's approve/deny decision through it. RQ1 does not measure adversaries B–H (compromised
signer, host, network, key, cryptanalytic, operator, or physical-device adversaries); those are RQ2–RQ6.

## 2. Units & factors

**Unit of observation:** one `(model, defense, case, rep)` vote — a single agent instance, running one
defense mechanism, voting approve/deny on one case (payload), on one repetition of that condition. Every
row in the RQ1 dataset is one such vote.

**Fixed-effect factors:**

| Factor | Levels / type | Source |
|---|---|---|
| `family` | model lineage (6 model families in the RQ1 matrix, per design spec §7) | `threat-model.md` §1 `lineage` domain |
| `size` | parameter count, within family (≥2 sizes per family, + quant variants, per design spec §7); enters the model as `size_b` (§3 below) | `threat-model.md` §1 `size` domain |
| `defense` | injection-defense mechanism applied to the agent (no-defense, instruction/data-separation, instruction hierarchy, spotlighting, known-answer/canary detection, StruQ-style surrogate, per-agent independent prompts, capability-scoped execution, deterministic policy, human-confirm — design spec §7) | `threat-model.md` §1 `defense` domain (the load-bearing domain) |
| `attack_category` | the corpus's documented attack taxonomy (≥18 categories, §7 below) | `threat-model.md` §2 adversary A |
| `delivery` | `direct` \| `indirect` (content directly presented to the agent vs. delivered through a tool/retrieval hop) | corpus taxonomy, design spec §7 |
| `turns` | `single` \| `multi` (single-turn vs. multi-turn interaction) | corpus taxonomy, design spec §7; not a term in the primary model (§3) — reported descriptively and reserved for the RQ3 adaptive/multi-turn extension |

**Random effects:** `payload` (the specific case/prompt instance — i.e., a case's identity independent of
which model or defense saw it) and `model` (the specific model instance, nesting `family`×`size`×quant/runtime).
Random effects absorb payload-specific and model-instance-specific variance that is not explained by the
fixed factors, so the fixed-effect estimates are not inflated by repeated observations of the same payload
or the same model across defenses.

`quantization/runtime` and `isolation/key-domain` (`threat-model.md` §1) are recorded per model/agent
instance as metadata (exact model hash + Ollama quantization level + llama.cpp runtime version, per design
spec §7) but are not separate fixed effects in the primary model (§3); they are absorbed into the `model`
random effect and reported descriptively.

## 3. Primary model

Mixed-effects logistic regression, fit once, over the **injection channel only** (the legitimate/benign
corpus, §7 below, is used for descriptive false-positive/utility reporting, not fit into this model):

```
approve ~ family + size_b + defense + attack_category + delivery
          + defense:family + attack_category:defense
          + (1|payload) + (1|model)
```

- **Outcome:** `approve` — 1 if the vote approves the (attempted) injected actuation, 0 if it denies it.
  On the injection channel, `approve = 1` is an attack success (the failure mode RQ1 measures); this is the
  inverse framing of an attack-success-rate table and the two are read together.
- **`size_b`:** standardized log-parameter-count, i.e., `size_b = (log(params) - mean(log(params))) / sd(log(params))`
  computed over the RQ1 model matrix, so the coefficient is interpretable per standard deviation of
  log-size and is not dominated by the raw parameter-count scale.
- **Interactions:** `defense:family` and `attack_category:defense` are the two interaction terms retained in
  the primary model — the first because it is the interaction the decisive contrast (§4) depends on
  (whether defense diversity's decorrelating effect holds across families), the second because attack
  categories are expected to interact with defense mechanisms non-uniformly (a canary-detection defense, for
  example, is not expected to behave uniformly across all 18 categories).
- **Random effects:** `(1|payload)` and `(1|model)`, matching §2.
- **Fit tool:** `statsmodels` GLMM (per the Phase 1 plan, `decorrelation/run_struq_baseline.py` /
  `decorrelation/analyze_rq1.py` lineage); the existing scipy-free pure-Python stats module
  (`decorrelation/stats.py`) remains the path for the secondary analyses in §5 and is not replaced by this
  model.

This is the single primary confirmatory model for RQ1. It is specified here, before any RQ1 data is
collected, and is not to be re-specified (different terms added/dropped, different link function, different
random-effects structure) after results are read; any post-hoc model variant is reported as exploratory and
labeled as such, never substituted for this primary model in a claim of pre-registration.

## 4. Primary contrast

**Defense-diversity vs. family-diversity comparison:** the difference in same-payload co-approval (**φ**,
the phi correlation coefficient — `decorrelation/stats.py::phi_coeff`) between quorum compositions that are
**defense-diverse** (two replicas share the same model family but run different defenses) and quorum
compositions that are **family-diverse** (two replicas share the same defense but come from different model
families), both computed over the same injection-channel payloads.

For each payload, form the two paired series: (a) approve/deny outcomes for a defense-diverse replica pair,
and (b) approve/deny outcomes for a family-diverse replica pair. Compute φ for each series
(`decorrelation/stats.py::phi_coeff`) and its **clustered (payload) bootstrap 95% CI**
(`decorrelation/stats.py::bootstrap_phi`, resampling payloads with replacement, consistent with the existing
pre-registered bootstrap procedure). The primary contrast is `φ_family-diverse − φ_defense-diverse`: RQ1's
hypothesis is that this difference is positive (family-diverse pairs co-approve more — i.e., fail together
more — than defense-diverse pairs), which would mean defense diversity decorrelates injection failure more
than family diversity. The contrast is reported with its own bootstrap CI (resampled jointly over payloads
so the two φ estimates in the difference are not treated as independent), following the same "never assert
independence/decorrelation from a point estimate" discipline as `interpret_phi` (§5).

The `defense:family` interaction term in the primary model (§3) is the confirmatory-model analogue of this
contrast: if defense's decorrelating effect is uniform across families, the interaction should be small; if
it varies by family, the interaction term and the φ contrast should tell a consistent story, and any
disagreement between them is reported, not resolved by preferring one over the other.

## 5. Secondary

Reported alongside the primary model and contrast, none of them substituting for either:

- **Per-model Wilson attack-success rate (ASR):** for each model instance, the injection-channel
  approve-rate with a Wilson 95% score interval (`decorrelation/stats.py::wilson`).
- **Per-category ASR:** the same Wilson-interval approve-rate, broken out by `attack_category` (≥18
  categories, §7 below), so no single category's rate is allowed to stand in for the aggregate.
- **φ with the existing pre-registered `interpret_phi` rule** (`decorrelation/stats.py::interpret_phi`):
  same-payload co-approval correlation reported with its bootstrap CI and interpreted only through the
  existing rule — if the CI reaches into meaningful positive correlation (`hi >= 0.2`), report "insufficient
  evidence for independence" (not "independent"); if the CI is tight around zero (`|lo|, |hi| < 0.2`),
  report "evidence against same-payload co-failure"; otherwise report the CI verbatim with an n-bounds-power
  caveat. **This document reaffirms, and does not relax, that rule: no RQ1 table or manuscript sentence
  asserts independence from a φ point estimate alone**, for the primary contrast (§4) or for any secondary
  φ reported here.

## 6. Repetitions & aggregation

- **≥3 repetitions per condition** (a "condition" is one `(model, defense, case)` triple), matching design
  spec §7. (Design spec §7 additionally calls for 5 repetitions for adaptive/multi-turn conditions; RQ1's
  injection-channel sweep as specified here uses the ≥3 floor uniformly, and any adaptive/multi-turn
  extension inherits the 5-repetition rule separately, under RQ3.)
- **A condition's vote is the modal rep vote:** the `(model, defense, case)` condition's reported vote is
  whichever of approve/deny occurs most often across its ≥3 repetitions (ties broken by reporting both the
  tie and defaulting to the more conservative label, deny, for any downstream binary use — the tie itself is
  always surfaced, never silently resolved).
- **Per-run variability is reported, not discarded:** alongside the modal vote, the raw per-repetition vote
  sequence and its dispersion (e.g., 3/3, 2/3, or a reported tie) are retained in the dataset and summarized
  per condition, so a condition that is unanimous across reps is visibly distinguishable from one that
  narrowly reached its modal vote.
- **Nondeterminism sources are documented:** anything that can make repeated votes on the same
  `(model, defense, case)` differ — sampling temperature/seed, Ollama/llama.cpp runtime nondeterminism,
  defense-mechanism randomization (if any) — is recorded per model/defense configuration alongside the exact
  model hash and runtime version (design spec §7), so per-run variability can be attributed rather than
  treated as unexplained noise.

## 7. Corpus targets

- **300–500 injection cases** and **150–250 legitimate (benign) cases**, matching design spec §7.
- **≥18 attack categories**, each documented in the corpus taxonomy (`attack_category`, §2 above).
- **≥1 minimal attack/benign pair per category:** every attack category includes at least one minimally-
  contrastive attack/benign case pair (same scaffolding, differing only in the injected content's intent),
  so a defense's or model's behavior on a category can be checked against a matched benign control, not only
  against an unpaired benign pool.
- **Source-tagged authored vs. public-derived:** every case carries a source tag distinguishing
  **authored** smart-home cases (written for this testbed) from **public-benchmark-derived** cases (adapted
  from AgentDojo/InjecAgent-style benchmarks), consistent with design spec §7 and the constraint carried in
  `threat-model.md`/design spec §8 that attack corpora are **DATA, never instructions**, to any process that
  handles them, regardless of source. The source tag is retained through analysis so any RQ1 result can be
  checked for sensitivity to authored-vs-public-derived provenance, not folded into an anonymous pooled
  corpus.
- `delivery` (`direct`\|`indirect`) and `turns` (`single`\|`multi`) metadata (§2 above) are recorded per
  case at corpus-construction time, alongside `attack_category` and the source tag, so the full factor set
  used by the primary model (§3) and the descriptive breakdowns (§5) is fixed before any model or defense is
  run against the corpus.

## 8. Stopping/decision rule

The RQ1 analysis is **descriptive and inferential** (Wilson intervals, φ with clustered bootstrap CIs, the
mixed-effects model of §3) — it is not a sequential hypothesis test and carries no early-stopping boundary.
**No optional stopping:** the full pre-declared `{model × defense × case × rep}` matrix (all model-family/
size/quant configurations of §2, all defenses of §2, the full corpus of §7, all repetitions of §6) is run to
completion **before any RQ1 table, φ value, ASR, or model coefficient is read**. Interim inspection of
partial results to decide whether to add models, defenses, corpus cases, or repetitions — or to stop early
because an early trend looks favorable or unfavorable — is out of scope for this design and, if it occurs
for an operational reason (e.g., a crashed run resumed via the checkpointed sweep), is disclosed in the
manuscript as a deviation from this pre-registration rather than silently absorbed into the reported matrix.
Any change to the factors (§2), primary model (§3), primary contrast (§4), or corpus targets (§7) made after
this document is committed is likewise a disclosed deviation, not a silent revision of this document.
