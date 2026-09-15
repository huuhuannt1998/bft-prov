# Task 4 (RQ1) — Qiskit Aer Shor-forgery of a classical provenance signature

`shor_forgery.py` — runnable on the Aer **simulator only** (no real/paid QPU, per scope).
Qiskit 2.4.2 / qiskit-aer 0.17.2 on Apple M4. Run: `python3 shor_forgery.py`.

## What it does
1. **Period-finding** for `7^x mod 15` via quantum phase estimation on `AerSimulator`
   (8 counting + 4 work qubits; canonical `c_amod15` modular-multiplication circuit). Classical
   post-processing reduces each measured phase to the **minimal** period `r = 4` (reliable: 6/6 runs).
2. **Factor** `N = 15 = 3 × 5` from `r`, recover `φ(N) = 8`, and invert `e` to get the RSA
   **private key `d`** — *from the public key `(N, e)` alone*.
3. **Forge** a textbook-RSA signature on a smart-home provenance record
   (`actuate:unlock_front_door|agent=home-llm|nonce=…`) that the classical verifier **accepts** —
   an actuation the honest agent never decided.

## The two-level correspondence (RQ1's whole point)
| Concrete (this script, Qiskit Aer) | Symbolic (`formal/tamarin/attribution_classical.spthy`) |
|---|---|
| Shor factors `N` | rule `Shor_break_classical`, fact `!ShorOracle(pkC(sk), sk)` |
| recover `d` from `(N, e)` | `Out(skC)` derivable given `In(pkC(skC))` |
| forged sig accepted by verifier | `Guard_Approve_and_Commit` accepts forged `sig` |
| actuation with no genuine decision | `Actuate(A,x)` with no `AgentDecide(A,x)` → **P1 & P3 falsified**, `forgery_reachable` verified |

The ML-DSA chain (`attribution_pqc.spthy`) has **no** such oracle, so the same forgery is
**unreachable** — which is exactly the contrast the Phase-1 gate asks for.

## Honesty / scope
`N = 15` is a 4-bit **toy** modulus: the Aer simulator cannot factor a real 2048-bit RSA modulus.
The demo shows the **mechanism** (public key → private key → universal provenance forgery), i.e.
*why* the chain must use ML-DSA rather than RSA/ECDSA — it is **not** a break of deployed RSA, and
uses no real quantum hardware. The symbolic-quantum-adversary modeling device is **not** claimed as
novel (precedent cited in the threat model).
