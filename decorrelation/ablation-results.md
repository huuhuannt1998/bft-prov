# Phase 3a Task 5 — provenance-prompt ablation (the framing decision)

Per `dec_01KVXKX14514PJSN3AJ5MT1Z4B`: the integrated-vs-free-text comparison confounded two variables
(output structure + the shared provenance prompt). This ablation holds the vote path FIXED (explicit
APPROVE/DENY on a proposed action) and varies ONLY the shared instruction-data-separation directive.
N=4/f=1, quorum=3, same 12-injection corpus, real model votes. No tuning.

## Headline: protection evaporates without the shared prompt
| Quantity | provenance ON | provenance OFF |
|----------|:--:|:--:|
| **Quorum defeats** (>= 3 families approve an injected unsafe action) | **0 / 12** | **10 / 12** |
| **Mean injected ASR** | 12% | **69%** |
| Baseline honest-error (llama / qwen / mistral / gemma) | 0 / 0 / 33 / 8% | **67 / 8 / 92 / 92%** |
| Injected ASR (llama / qwen / mistral / gemma) | 0 / 0 / 50 / 0% | 83 / 17 / 92 / 83% |

## What this settles (reading #2, the less flattering one)
**The shared provenance / instruction-data-separation prompt is the heavy lifter, not the diversity
and not the voting structure.** With the vote path identical and only the shared directive removed,
quorum defeats go from 0/12 to 10/12 and mean ASR from 12% to 69%.

Three consequences, all honest:
1. **The prevention is a single, shared defense, correlated across families BY CONSTRUCTION.** With the
   prompt off, the SAME injections defeat the quorum (10/12 reach >= 3 approving families): the families
   fail TOGETHER, not independently. An adaptive attacker who defeats the instruction-data separation
   defeats it in every family that relies on it. This is the opposite of the BFT fault-independence the
   quorum model assumes.
2. **The earlier universal-transfer finding is REAL and relocates, it is not an artifact.** Without the
   prompt, subtle injections flip all four families (e.g. `subtle-door`, `subtle-door2`), reproducing
   the earlier result. It is evidence that the underlying models are **correlated-vulnerable**; the
   deployed prompt suppresses it; the suppression is the thing an adaptive attack will target.
3. **The diversity claim shrinks to: at f=1, the quorum tolerates ONE weak family (mistral) WHILE the
   shared prompt carries the rest.** That is heterogeneous per-family competence tolerated at f=1, not
   demonstrated fault-independence (unknowable at N=4 with one outlier).

## The one genuine diversity signal (stated carefully)
`qwen` is a real outlier: even with the prompt OFF its baseline error is 8% and ASR 17%, while
llama/mistral/gemma are 67-92% susceptible without the prompt. So qwen has genuine judgment robustness
the others lack. That is real per-family heterogeneity, but one robust family out of four does not earn
an independence claim, and qwen alone cannot carry a 2f+1 quorum.

## Caveats (no overclaiming in either direction)
- Temperature-0 is **not** deterministic (a spot re-run flipped a vote); both columns are
  **direction-level**, not confident rates. The ON/OFF gap (0/12 vs 10/12, 12% vs 69%) is far larger
  than the observed noise, so the direction is solid; the exact rates are Phase 4 (repeats, held-out, CIs).
- Small hand-crafted corpus; the subtle injections are non-adaptive. Adaptive evasion of the shared
  prompt is the key untested threat (Phase 4).

## Paper center of gravity (for Task 6 §5 / Claim B)
- **Prevention (Claim B):** the deployed system suppresses these injections with a **shared
  instruction-data-separation prompt** (ON: 0/12 defeats); this defense is **correlated across families
  by construction** (OFF: 10/12 defeats, families fail together), so it does **not** establish BFT
  fault-independence; the diversity amounts to tolerating one weak family at f=1; and an adaptive
  attacker targeting the shared prompt is untested. Prevention is bounded and measured, not a guarantee.
- **Attribution (Claim A):** unconditional; the attribution floor (Task 4) holds regardless of which
  mechanism provides prevention, which is exactly why it, not the prevention layer, is the system's real
  guarantee. The ablation strengthens the spine: the more the prevention is shown to be a single
  correlated defense, the more the unconditional attribution floor is what the paper actually stands on.
