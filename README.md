# Correlated failures in replicated LLM agents, and an accountable actuation path

Research artifact for a manuscript currently under double-anonymous review. The manuscript title,
its venue, and author identification are all omitted here for the duration of that review, so that
this repository does not link the paper to its authors.

Replicating an LLM agent and requiring a quorum before a high-risk actuation is only as good as the
assumption that replicas will not approve the same attack. This artifact contains the measurement that
tests that assumption, the quorum evaluation that follows from it, and the accountable-actuation path
built on the result.

## What is here

| Component | Path |
|---|---|
| Attack, legitimate-task and control corpora | `decorrelation/corpus_main.py`, `decorrelation/injections.py`, `decorrelation/controls_expanded.py` |
| Six prompt-level defenses | `decorrelation/defenses.py` |
| **Raw per-repetition votes, 78 agents** | `decorrelation/rq1/*.json` |
| Dependence and quorum analysis | `decorrelation/analyze_quorum.py`, `decorrelation/canonical_quorums.py` |
| Deterministic policy verifier (24 rules) | `agent/guard/verifier.rego` |
| Certificate schema, replay and epoch commit store | `consensus/cert_schema.py` |
| Certificate overhead, faults, verifier evaluation | `eval/` |
| Constrained-platform benchmark | `edge/bench_gateway.py`, `edge/Dockerfile.constrained` |
| Machine-checked domain-coverage model | `formal/tla/DomainCoverage.tla` |

`ARTIFACT.md` maps every number in the paper to the file and command that produces it.

## Study design

An **agent** is one (model configuration, defense) pair: 13 local model configurations under 6 defenses
= 78 agents. The 65 agents carrying a defense form the *deployable pool*.

- **Models:** `gemma2:9b`, `gemma3:4b`, `granite3.1-dense:8b`, `granite3.1-moe:3b`, `llama3.1:8b`,
  `llama3.2:3b`, `llama3.2:3b-instruct-q8_0`, `mistral-nemo:12b`, `mistral:7b`, `phi3.5:3.8b`,
  `phi4-mini`, `qwen2.5:3b`, `qwen2.5:7b` — all served locally by Ollama.
- **Defenses:** none; instruction and data separation; a structured-query surrogate of StruQ;
  instruction hierarchy; spotlighting with datamarking; known-answer canary. The hierarchy and
  structured-query defenses are prompt-level surrogates, not retrained models.
- **Corpora:** 342 indirect-injection payloads over 18 categories at three sophistication levels, 168
  legitimate tasks, and 54 matched benign controls (18 original, plus 36 whose ingested text
  *resembles* an injection without carrying authorization).
- **Decoding:** temperature 0, three repetitions, 123,552 decisions in total.

Payloads are handled strictly as data and never executed as instructions. All models and devices are
local; actuation is emulated through Home Assistant virtual devices.

### Raw vote format

Each file in `decorrelation/rq1/` is one agent. `raw` maps payload id to the list of per-repetition
boolean approvals, so every derived rate in the paper can be recomputed from source:

```json
{"tag": "gemma2:9b", "defense": "hierarchy", "reps": 3,
 "raw":          {"fua-0": [false, false, false], "fua-1": [false, false, false]},
 "raw_legit":    {"...": []},
 "raw_controls": {"...": []}}
```

## Headline results

- Replicas reading the same injected content approve together more often than a pooled independence
  model predicts: 1.10× for family-diverse pairs and 1.09× for jointly diverse pairs, with two-way
  (agent × payload) cluster-bootstrap intervals excluding independence. This is *shared-input*
  dependence; it does not identify a model-lineage common cause.
- Homogeneous replication leaves attack success unchanged at every threshold, 19.2–19.3% from 1-of-5 to
  5-of-5, where independence predicts a fall from 36.3% to 8.0%.
- Diverse quorums help by less than predicted, and the shortfall grows with the threshold: 1.18× at
  3-of-5 to 2.18× at 5-of-7.
- The paper therefore treats the quorum as a bounded filter, enforces safety in a deterministic verifier
  outside the models, and binds every committed actuation to a signed certificate in a tamper-evident
  log.

## Reproducing

Analyses run offline from the shipped raw votes. Only re-running the sweep itself needs local models.

```bash
export PYTHONPATH=.

# quorum and dependence tables (offline, from decorrelation/rq1/)
python -m decorrelation.canonical_quorums
python -m decorrelation.analyze_quorum

# control and adaptive analyses (offline)
python -m decorrelation.analyze_controls
python -m decorrelation.analyze_adaptive

# system evaluation (needs opa on PATH; liboqs for the certificate paths)
python -m eval.verifier_eval
python -m eval.verifier_contexts
python -m eval.cert_scaling
python -m eval.fault_injection
```

Requirements: Python 3.11+ with `numpy` and `scipy`; `liboqs`/`oqs` bindings for ML-DSA; OPA on `PATH`
for the verifier; Ollama only if re-running the sweep. Developed on Python 3.13 with numpy 2.4, scipy
1.17, OPA 1.17, liboqs 0.15.0 on the host and 0.16.0 in the container.

Temperature-0 decoding is near but not bit-reproducible (99.9% of cells are unanimous), so a fresh
sweep reproduces the paper at the direction and magnitude level, not digit for digit. Every analysis
over the shipped votes is seeded and reproduces exactly.

## Scope and limits

Stated so the artifact is not read for more than it shows. Actuation is emulated, so physical failure
modes are modeled rather than observed. Agents hold distinct logical signing keys but share one process
on one host, so the prototype supplies none of the process, key-store, or machine independence a
deployment would want. The constrained measurement in `edge/` fixes operating system, instruction set,
core count and memory but not microarchitecture. The verifier scores 140 of 150 on the sealed Audit
Set 2, with 6 false permits and 4 false denials; the 54-case context matrix that preceded it is
diagnostic rather than held-out, because its failures drove the fail-safe repair. The domain-coverage theorem is machine-checked at one bounded configuration and concerns
certificate formation, not semantic safety.

## License

MIT — see `LICENSE`. Manuscript sources are not distributed in this repository.
