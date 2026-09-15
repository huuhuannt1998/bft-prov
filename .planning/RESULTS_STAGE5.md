# Results — Stage 5, the authoring attacker (the gate)

Run under `.planning/PREREGISTRATION_STAGE5_v2.md`, frozen and committed at `65762e6` before the v2
grammar was generated. Screen only: 12 agents × 100 authored payloads × 1 repetition = 1,200
inferences. **The full 66,690-inference arm was not authorised and was not run.**

## Verdict: E3

| Criterion | Threshold | Result | |
|---|---|---|---|
| S-A granite-arm minus mistral-arm differential | > 34.3 pp | **−15.0 pp** | fail |
| S-B minimum cross-family $\rho$ | < −0.168 | **+0.084**, 0 undefined pairs | fail |
| Validity precondition | both target families non-zero, no NaN | satisfied | ok |

Neither G1 nor G2 fires, so by the preregistration this is **exit E3: one-dimensionality is
structural, not an artifact of one corpus.** The preregistration predicted E2 or E3.

## This is a failure to differentiate, not a failure to attack

The distinction the validity precondition exists to enforce, and it lands on the right side.
**Overall authored-corpus attack success was 60.8 %**, against roughly 24 % for the natural corpus.
The grammar attacked extremely well:

| Family | granite arm | mistral arm | arm effect |
|---|---|---|---|
| gemma | 100.0 % | 90.0 % | +10.0 pp |
| granite | 80.0 % | 60.0 % | +20.0 pp |
| llama | 80.0 % | 30.0 % | +50.0 pp |
| mistral | 99.0 % | 64.0 % | +35.0 pp |
| phi | 79.0 % | 42.0 % | +37.0 pp |
| qwen | 6.0 % | 0.0 % | +6.0 pp |

Every family produced attacks. Nothing was degenerate. The measurement was capable of detecting
targeting and detected none.

## The targeting did not merely fail — it inverted

The granite arm was built from the cells measured most granite-favouring on the natural corpus. On
authored payloads it did not favour granite:

- granite-minus-mistral on granite-arm payloads: **−19.0 pp**
- granite-minus-mistral on mistral-arm payloads: **−4.0 pp**
- S-A = **−15.0 pp**, where a positive 34.3 was required

Read down the arm-effect column instead and the reason is visible: the granite arm raised *every*
family, by +6 to +50 pp. It is a better attack, not a targeted one. The rules that discriminated
between families on the natural corpus became a general-purpose potency lever once authored
deliberately.

That is the sharpest form of the one-dimensionality result this project has produced. A grammar
built specifically to separate two model families, using features measured to separate them,
separated nothing — it just moved everything up the single axis.

## What this settles, and what it does not

**Settles.** Selection cannot break one-dimensionality (Stages 2–4) and neither can authoring, at
least not authoring driven by the feature structure the natural corpus exposes. The floor becomes
the whole paper, and it is stronger for having survived a deliberate attempt to break it.

**Does not settle.** This is a 12-agent, 100-payload screen, not the 65-agent full arm. It is
adequate to reject targeting — the effect is negative where a large positive was required, so no
plausible power gain reverses it — but the full arm would be needed to quote a precise
cross-family $\rho$ on authored payloads. Nothing in the paper needs that number.

The grammar is also one grammar. A different attacker, or one with white-box access, might find an
axis this one did not. The claim is bounded to what was tested: **feature-driven authoring, built
from the discriminative structure of a 342-payload corpus, does not break one-dimensionality.**

## Stage 6

Remains unrun and correctly gated: it refuses without an E1 exit. Composition knowledge did not
acquire value, so hiding the composition defends against nothing.

## Cost

1,200 inferences, about 55 minutes. The full arm would have been 66,690 inferences and roughly 33
hours weighted by measured per-model rates. **The screen returned the same verdict for 1.8 % of the
cost**, which is what it was built to do.
