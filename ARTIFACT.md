# Artifact Evaluation Guide

Artifact for *"Correlated Prompt-Injection Failures in LLM-Agent Quorums for Accountable Smart-Home
Actuation"* (submitted to ACM Transactions on Internet of Things). This guide maps each reported number to the file that
holds it and the command that regenerates it. All paths are relative to the repository root; run with
`export PYTHONPATH=.`.

The artifact splits into three parts by what they need:

- **Offline** — every empirical result in Section III recomputes from the shipped raw votes in
  `decorrelation/rq1/`. No models, no network.
- **Local tools** — the verifier, certificate and fault results in Section VII need OPA and liboqs, but
  no models.
- **Local models** — only re-running a sweep needs Ollama serving the 13 configurations.

## 0. Environment

- Python 3.11+ with `numpy` and `scipy`. Developed on Python 3.13, numpy 2.4.3, scipy 1.17.1.
- `oqs` (liboqs bindings) for ML-DSA. Host measurements used liboqs 0.15.0; the constrained container
  pins 0.16.0.
- OPA on `PATH` for the deterministic verifier. Developed against OPA 1.17.1.
- Apalache for the coverage model (Section VI).
- Ollama only if re-running a sweep. Actuation is emulated throughout; no physical hardware is used or
  required.

## 1. Section III — shared unsafe approval

The single source for every quorum number is `decorrelation/canonical_quorums.py`. It samples member
sets **once** per (composition, N) under a fixed seed, assigns each a stable identifier, and scores that
one draw under the static, verifier-combined and adaptive conditions, so an identifier denotes the same
member sets everywhere it appears. `make_supp_quorum_table.py` renders the supplementary grid from the
same file, which is why the main and supplementary quorum tables cannot disagree.

| Paper result | Command | Artifact |
|---|---|---|
| Table I, pair-category dependence (1.10×, 1.09×, φ) | `python -m decorrelation.analyze_quorum` | `decorrelation/dep_agentcluster.json` |
| §III-B covariance decomposition (total 0.0079, within-payload zero) | same | `decorrelation/quorum_analysis.json` |
| Table II, canonical quorum outcomes (`HOM-3of5`, `JD-4of7`, …) | `python -m decorrelation.canonical_quorums` | `decorrelation/canonical_quorums.json` |
| Supplementary Table S3, all nine rules at every threshold | `python -m decorrelation.make_supp_quorum_table` | rendered from the same JSON |
| §III-C per-defense ASR and utility (62.6% → 16.5%) | `python -m decorrelation.analyze_quorum` | `decorrelation/rq1/*.json` |
| §III-C matched controls, 17.6% over 54 controls | `python -m decorrelation.analyze_controls` | `decorrelation/controls_analysis.json` |
| §III-E adaptive stress test, 24.3% → 39.8% | `python -m decorrelation.analyze_adaptive` | `decorrelation/adaptive_analysis.json` |

Re-running the two sweeps (needs Ollama):

```bash
python -m decorrelation.run_controls_expanded   # -> decorrelation/controls_expanded.json  (~65 min)
python -m decorrelation.run_adaptive_pool       # -> decorrelation/adaptive_pool.json      (~65 min)
```

**Held-out discipline.** Payloads split in half stratified by attack category, 162 training and 180
held-out. Data-driven composition rules (`lowest-ASR`, `best-security-utility`, `max-diversity`) select
on the training half only; every strategy is scored on the held-out half. The `BSU-3of5` utility figure
is in-sample, because that rule saw all legitimate tasks, and the paper says so.

**Reading a quorum number.** For agent *i* and payload *x*, `p_i(x)` is the fraction of three
independent invocations that approved. A *q*-of-*N* outcome is the Poisson-binomial probability that at
least *q* of *N* independent invocations approve — a simulation over independently sampled invocations,
not one observed vote tally. Homogeneous quorums are therefore counterfactual: they reuse one
configuration's `p_i(x)` *N* times, and since only three invocations per cell were run, N>3 homogeneous
quorums are simulated from the estimated rate rather than observed directly.

## 2. Section VI — machine-checked domain coverage

The theorem is that a coverage predicate excludes coalitions a bare count threshold admits, under an
adversary structure of unions of at most T declared domains.

```bash
apalache-mc check --inv=CoverageInv formal/tla/MC_Coverage_OK.tla      # MinDomains=3 > T=2: holds
apalache-mc check --inv=CoverageInv formal/tla/MC_Coverage_Count.tla   # count-only: counterexample
```

The model is `formal/tla/DomainCoverage.tla`. The second configuration is the point: it *should* fail,
and its counterexample is the certificate a count threshold would have admitted. This is bounded model
checking at one configuration and concerns certificate formation, not semantic safety.

## 3. Section VII — system evaluation

| Paper result | Command | Artifact |
|---|---|---|
| 24-rule bundle, 42/42 policy-intent suite; 0.36 ms mean, 0.53 ms p95 | `python -m eval.verifier_eval` | `eval/verifier_eval.json` |
| Held-out coverage audit over 19 action classes | `python -m eval.verifier_ablation` | `eval/verifier_ablation.json`, `eval/action_split.json` |
| Audit Set 1 (context matrix), diagnostic: 51 of 54 post-repair, 0 false permits, 3 false denials | `python -m eval.verifier_contexts` | `eval/verifier_contexts.json` |
| **Audit Set 2 (sealed), the reported coverage result: 140 of 150, 6 false permits, 4 false denials** | `python -m eval.audit_set2` | `eval/audit_set2.json`, `eval/audit_set2_manifest.json` |
| Tiered operating point, Table IV acceptance columns | `python -m eval.tiered_operating_point` | `eval/tiered_operating_point.json` |
| Repair audit, development vs held-out action classes | `python -m eval.verifier_repair_audit` | `eval/verifier_repair_audit.json` |
| Table III, quorum × verifier combined | `python -m decorrelation.canonical_quorums` | `decorrelation/canonical_quorums.json` |
| Complete certificate overhead, 918 + 6795q bytes, R²=1.0000 | `python -m eval.cert_scaling` | `eval/cert_scaling.json` |
| Fault matrix, 486 trials with honest controls | `python -m eval.fault_injection` | `eval/fault_injection.json` |
| Model vote latency, 664–1046 ms per-model mean | — | `eval/inference_latency.json` |

**Three verifier claims that are easy to conflate**, separated deliberately in the paper:
*rule conformance* is the 42-case suite written alongside the rules, a regression test and not a
generalization benchmark; *coverage* is the sealed Audit Set 2 result; *combined effectiveness* is the
quorum-by-verifier table.

The audit sets are not interchangeable, and an earlier version of this guide reported the wrong one.
Audit Set 1 is the 54-case context matrix. Its pre-repair score of 34 of 54 with 20 false permits is
what motivated the fail-safe repair, so its post-repair score of 51 of 54 is **in-sample and
diagnostic** — it cannot be read as coverage. Audit Set 2 is generated over 25 devices appearing in
neither the rule set nor Audit Set 1, with every expected decision fixed from policy intent before the
engine runs. Its 140 of 150 is the coverage number the paper reports.

Reproducing Audit Set 2 requires the committed `agent/guard/verifier.rego`. The bundle is the input to
this measurement, so a modified working tree will produce a different score.

### Constrained-platform measurement

```bash
docker build -f edge/Dockerfile.constrained -t pqbft-edge .
docker run --rm pqbft-edge                                   # unconstrained container
docker run --rm --cpus=1 --memory=512m pqbft-edge            # constrained
python -m edge.bench_gateway --iters 15 --policy-iters 200    # host, for context
```

Results ship as `edge/results_container_full.json`, `edge/results_container_1cpu512m.json` and
`edge/results_Huans-MacBook-Pro.json`. The contrast the paper draws is constrained container versus
unconstrained container, both at liboqs 0.16.0, so it stays within one software stack. **This is not a
Raspberry Pi and is never labelled one.** It fixes operating system, instruction set, core count and
memory, but the underlying cores remain Apple M4 rather than a Cortex-A class part, so it is a
constrained-resource measurement, not a gateway-class one.

## 4. What is implemented and what is not

Implemented and exercised: the enrollment registry, the replay and epoch commit store, revocation, the
24-rule verifier, the Merkle log, post-quantum signing, and the actuation lifecycle
(`consensus/cert_schema.py`, `agent/guard/verifier.rego`).

Not implemented, and no claim in the paper rests on them: separate processes or key stores, multi-host
deployment, an external log witness, and any physical device. Supplementary Table S4 states this per
component. The log's delivered property is tamper evidence under a consistent externally retained
checkpoint, not public verifiability, because no external witness is implemented.

## 5. Reproducibility notes

- Analyses are seeded (`SEED = 20260801`); the payload split is stratified by attack category; the
  frozen analysis plan predates the sweep and ships with the artifact.
- Temperature-0 decoding is near but not bit-reproducible: 99.9% of (agent, payload) cells are
  unanimous. A fresh sweep reproduces the paper at the direction and magnitude level. Every analysis
  over the shipped votes reproduces exactly.
- The frozen confirmatory regression did not converge, so family and size effects are reported as
  descriptive and no coefficients from it appear in the paper.
- Every payload is handled as data and never executed as an instruction. Models and devices are local
  and emulated.
