# Task 6 — ProVerif secondary cross-check (comparison note)

ProVerif 2.05 (built CLI-only from source; the lablgtk2 GUI was skipped — see env note). Applied-pi
re-expression of the provenance-to-actuation chain, cross-validating the Tamarin results of Task 2.

## Results

| Query | `attribution_pqc.pv` (ML-DSA, key secret) | `attribution_classical.pv` (Shor leaks key) |
|-------|--------------------------------------------|---------------------------------------------|
| non-injective `event(Actuate(x)) ⟹ event(AgentDecide(x))` (= P1 authentication) | **true** | **false** (forgery) |
| injective `inj-event(Actuate(x)) ⟹ inj-event(AgentDecide(x))` (= P3) | false* | **false** (forgery) |

## Where the two tools AGREE (the load-bearing cross-validation)
- **Classical chain is forgeable under the quantum adversary in BOTH tools.** Tamarin: P1 & P3
  falsified with a Shor attack trace. ProVerif: both queries false once `out(c, skA)` models Shor
  key recovery. → The central RQ1/RQ2 *contrast* is tool-independent.
- **PQC chain provides authentication (P1) in BOTH tools.** Tamarin: P1 verified. ProVerif:
  non-injective correspondence true. → "No actuation without a genuine prior agent decision" is
  confirmed by an independent prover.

## Where the two tools DIVERGE (and why — a modeling-semantics difference, not a protocol attack)
`*` ProVerif reports the **injective** PQC query as *false*, whereas Tamarin **proves** injective
attribution-binding (P3). The cause is tool semantics, not a real replay attack:

- **Tamarin** models the one-shot commit with a **linear fact** (`Actuatable`, consumed exactly once)
  plus the `UniqueCommitPerNonce` restriction. Check-and-commit is atomic, so each decision yields at
  most one actuation → injectivity holds.
- **ProVerif** has only **persistent tables**; `get committed(=x) in 0 else (insert; event)` is not an
  atomic test-and-set across replicated guard instances, so ProVerif admits an interleaving where two
  guards both miss the table and both actuate. This is the well-known Tamarin-vs-ProVerif difference
  on stateful/injective non-repudiation (it is exactly why the FV-footing decision
  dec_01KVS3WK60WAPV8TS7QBZ108BM put **Tamarin primary** for the injective property and ProVerif as a
  cheap secrecy/authentication cross-check). The real provenance log is an atomic append-only
  structure, so the divergence reflects ProVerif's abstraction, not a vulnerability.

## Takeaway
The ProVerif cross-check **independently confirms** the two claims that matter most — classical chain
forgeable, PQC chain authenticated — and the one divergence is a documented and expected modeling
limitation that validates the original decision to use Tamarin as the primary prover for the
injective attribution-binding property. Files: `attribution_pqc.pv`, `attribution_classical.pv`,
outputs under `output/`.
