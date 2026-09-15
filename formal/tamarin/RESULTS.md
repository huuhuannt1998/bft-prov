# Task 2 — Tamarin results (RQ2 core)

Tamarin 1.12.0 (+ maude 3.5.1), Apple M4. Models cover the **core single-actuation case**
(one honest agent, one device class, verified guard/log, emulated actuator). Property vocabulary
per `docs/01-threat-model/system-and-threat-model.md`.

## Headline result (the RQ1↔RQ2 contrast)

| Lemma | `attribution_classical.spthy` (RSA/ECDSA + Shor) | `attribution_pqc.spthy` (ML-DSA, no forge) |
|-------|--------------------------------------------------|--------------------------------------------|
| `actuation_reachable` (exists) | verified (5) | verified (5) |
| `P1_authentication` (all) | **falsified — attack trace (7)** | **verified (8)** |
| `P2_policy_compliance` (all) | — | verified (3) |
| `P3_injective_attribution` (all) | **falsified — attack trace (9)** | **verified (19)** |
| `P4_logged_before_actuate` (all) | — | verified (3) |
| forgery lemma | `forgery_reachable`: **verified (9)** — attack exists | `forgery_unreachable_pqc`: falsified/no-trace — attack impossible |

- **Wellformedness:** 0 warnings on both files (the Shor capability is modeled via an explicit
  `!ShorOracle(pk, sk)` fact so the recovered key is derivable — no unintended pattern matching).
- **Termination:** both files complete in ≤ 0.3 s with the default heuristic; no oracle, no bounding
  needed. The PI's RAM/termination risk did not materialize for the core case.

### What the classical attack trace is (the "quantum forgery of the classical chain", RQ1 symbolic side)
`Register_Agent` (honest agent publishes `pkC`) → `Shor_break_classical` (quantum adversary recovers
`skC` from the public key via the `!ShorOracle`) → adversary forges `signC(x*, skC)` on an intent `x*`
the agent never decided → `Guard_Approve_and_Commit` accepts it (signature verifies) → `Actuate(A, x*)`
with **no** preceding `AgentDecide(A, x*)`. This both fabricates an actuation (P1) and mis-attributes it
to the honest agent (P3). It mirrors, symbolically, the concrete Qiskit Aer Shor-forgery of Task 4.

### What the PQC chain gives
With ML-DSA unforgeability retained (no forge rule, no Shor oracle), the only producer of a verifying
signature on `x` under `pkQ(A)` is the agent's own `Agent_Decide` — so P1, P2, P3 (injective
attribution-binding), and P4 all hold for the core case, and forgery is unreachable.

## BUFF sensitivity/fixed pair (the Task 2 ↔ Task 3 link, machine-checked)

To make the dependency in the caveat below *rigorous* rather than asserted, two further models
hold an EO-failing primitive fixed (extra equation `verifyQ(sig, m, spoofpk(sig,m)) = true`,
modeling key substitution à la Jackson et al., CCS 2019) and test exclusive-ownership-in-context —
"the key the log credits for an honest signature `(m, sig)` is the honest signer's key":

| Model | `EO_honest_signature_uniquely_credited` | Meaning |
|-------|------------------------------------------|---------|
| `attribution_buff_sensitivity.spthy` (no pk-binding) | **falsified — attack trace (8)** | without exclusive ownership, an honest signature is re-credited to a spoofed key |
| `attribution_buff_fixed.spthy` (BUFF transform: pk bound into the signed payload) | **verified (2)** | binding `pk` into the signed record restores attribution-binding **even when the primitive lacks EO** |

So P3's non-re-attribution clause provably **depends on exclusive ownership**, and a BUFF-style
pk-binding transform provably **restores** it. (0 wellformedness warnings on both.) The arrival of
the *correct* lemma took three formulations — earlier name-level and key-level lemmas conflated EO
with PKI-naming and nonce-binding artifacts; the final lemma holds the honest `(m, sig)` fixed,
which isolates exclusive ownership cleanly.

## ⚠️ BUFF caveat — the P3 claim is GATED on Task 3 (PI directive)

The equational theory `verifyQ(signQ(m,sk), m, pkQ(sk)) = true` makes a signature verify **only** under
the matching public key and **only** for the signed message. The symbolic model therefore **silently
assumes** two beyond-EUF-CMA (BUFF) properties:

- **Exclusive ownership (DEO):** a signature cannot be made to verify under a *different* public key.
- **Message-bound signatures (MBS):** a signature cannot be made to verify for a *different* message.

P3's *non-re-attribution* clause leans on exactly these. **The clean P3 proof above is faithful to
ML-DSA only if Task 3 confirms ML-DSA actually provides DEO/MBS/NR — or the BUFF-lifting transform
restores them.** Until Task 3 discharges this, the recorded state is: *"P3 proven under a signature
theory that assumes DEO/MBS,"* **not** *"P3 proven for ML-DSA."* The companion model
`attribution_buff_sensitivity.spthy` (built in Task 3) demonstrates that dropping DEO breaks P3 and that
the transform `sign(H(pk‖m))` restores it.

## Files
- `attribution_pqc.spthy` / `output/pqc_proof.txt`
- `attribution_classical.spthy` / `output/classical_proof.txt`
- `attribution_buff_sensitivity.spthy` (Task 3)
