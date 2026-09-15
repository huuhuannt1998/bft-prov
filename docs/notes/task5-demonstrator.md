# Task 5 (RQ3) — M4 provenance → emulated-actuation demonstrator

End-to-end proof-of-life on the MacBook M4 hub. **M4-only, emulated** actuation
(dec_01KVWZV01Z23GWW41451NH96X6) — no Pi, no GPIO, no physical device; never claim physical actuation.

## Components (all built fresh / greenfield)
| Module | Role |
|--------|------|
| `provenance/crypto/mldsa.py` | ML-DSA-44/65/87 sign/verify over liboqs; domain/context separator |
| `provenance/gateway/record.py` | decision→actuation record; **binds agent pk + domain into the signed payload** (Task-3 rule) |
| `provenance/log/merkle_log.py` | tamper-evident Merkle log (pymerkle), **ML-DSA-signed** leaves, **nonce dedup** (= `UniqueCommitPerNonce`) |
| `agent/guard/policy.rego` + `guard.py` | OPA/Rego runtime guard automaton — decision made **outside** the untrusted agent (P2) |
| `actuation/homeassistant/virtual_device.py` | emulated HA `input_boolean` virtual device (logged command) + live-HA REST drop-in |
| `agent/orchestrator/pipeline.py` | wires intent → guard → sign → commit → verify → actuate; optional Ollama untrusted-oracle hook |
| `eval/latency/bench.py` → `results.md` | ML-DSA + log + end-to-end latency table |

## What it demonstrates
The pipeline runs the three canonical cases: a **safe** action permits→signs→logs→verifies→actuates;
an **unauthorized hazardous** action (unlock door) is **denied** and never reaches the device; an
**authorized hazardous** action actuates. Verification before actuation checks: ML-DSA signature under
the **credited (bound) key**, pk-binding consistency, Merkle inclusion, and policy==permit — the
runtime mirror of the Tamarin lemmas P1/P2/P3/P4.

## Latency (feasibility on a capable hub — NOT a constrained-device number)
ML-DSA-65 sign ≈ 0.26 ms, verify ≈ 0.06 ms; Merkle commit+inclusion ≈ 0.29 ms; crypto+log+verify core
≈ 0.5 ms end-to-end. The only heavy stage is the OPA **CLI cold-start** (~10 ms/call), removed by a
long-running OPA server or the OPA SDK. Full table in `eval/latency/results.md`.

## Honesty / scope
- Actuation is **emulated**; M4 timing is "feasibility on a capable hub" only.
- The **LLM is untrusted**: `propose_intent` may consult a local Ollama model, but the guard — not the
  model — decides actuation; the demonstrator runs without a model pull (Ollama integration is the
  intended oracle source, wired but optional, to avoid a multi-GB download for the skeleton).
- ML-DSA primitive security is **assumed** from liboqs (verified impl), not re-proven.
