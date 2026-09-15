# ML-DSA BUFF / Non-Re-Signability Assessment — go/adjust memo (Task 3)

**Mission** `mis_01KVS3YJBEHQ3GD6Y5N6ZTJTSD`, Task 3 (RQ2 risk check). **Gates** the Task-2 P3
("injective attribution-binding for ML-DSA") final claim, per PI directive.

**Bottom line: GO.** The two beyond-EUF-CMA properties our attribution-binding actually needs —
**exclusive ownership** and **message-bound signatures** — are provided by standardized **ML-DSA
(FIPS 204)** per current literature, resting on SHAKE-256 collision resistance via the `tr = H(pk)`
binding. **Non-resignability**, the one BUFF property whose very definition is contested, is **not
load-bearing** for our property because we attribute to the *(key, decision-message)* and dedup by
nonce in the tamper-evident log. As defense-in-depth we nonetheless adopt an explicit
application-level BUFF binding (sign/log the record together with `pk_A` and a FIPS-204 context
string); a machine-checked model shows this restores attribution-binding *even if* a future result
weakened ML-DSA's exclusive ownership.

---

## 1. Why attribution-binding needs *beyond*-EUF-CMA properties

EUF-CMA (which we assume from verified implementations and do **not** re-prove) stops an adversary
from forging a signature on a *new* message under a key whose secret it lacks. It says **nothing**
about three re-attribution attacks that our property P3 (non-re-attribution) must exclude — the
**BUFF** features (Beyond UnForgeability Features; Cremers, Düzlü, Fiedler, Günther, Janson, *BUFF:
Beyond UnForgeability Features*, IEEE S&P 2021, ePrint **2020/1525** — the reference the mission flags):

| # | Attack on attribution | BUFF property that blocks it |
|---|------------------------|------------------------------|
| (a) | Re-credit an honest signature to a **different key** (key substitution / DSKS) | **Exclusive ownership** (CEO / DEO, and strong variants S-CEO / S-DEO) |
| (b) | Re-bind a signature to a **different message** (different device/command) | **Message-bound signatures** (MBS) |
| (c) | Derive a fresh signature on the **same (m, pk)** treated as a distinct authentic hop | **Non-resignability** (NR) |

Our Tamarin model (`formal/tamarin/attribution_buff_sensitivity.spthy`) makes (a) concrete and
machine-checked: with an EO-failing primitive, an honest signature is re-credited to a spoofed key
(lemma `EO_honest_signature_uniquely_credited` **falsified**). So the dependency is real, not
hypothetical.

## 2. What ML-DSA actually provides

**Exclusive ownership (a) and message-bound (b): YES.** ML-DSA folds a hash of the public key into
the message representative — `μ = H(tr ‖ M')` with `tr = H(pk)` and `M'` carrying a domain separator
and context string (FIPS 204). Because the public key is hashed into what gets signed, a signature
cannot be made to verify under a different `pk` (different `tr`) or for a different message without a
SHAKE-256 collision. This is exactly what *Exclusive Ownership of Fiat-Shamir Signatures: ML-DSA,
SQIsign, LESS, and More* (ePrint **2025/900**, 2025) proves: **ML-DSA has exclusive ownership
(and message-bound signatures), reducing tightly to SHAKE-256 collision resistance.** This is the
strong form (S-CEO/S-DEO) that P3's non-re-attribution clause needs.

**Non-resignability (c): theoretically contested, but NOT load-bearing for us.** The *original* BUFF
NR definition was shown **unachievable / proved via faulty argument** (Don, Fehr, Huang, Struck, *On
the (In)Security of the BUFF Transform*, ePrint **2023/1634**, CRYPTO 2024). Corrected, weaker NR
notions are achievable: a *salted* BUFF transform satisfies a statistical-entropy variant in the ROM,
classically and quantumly (*Hide-and-Seek and the Non-Resignability of the BUFF Transform*, ePrint
**2024/793**, TCC 2024), and *Sandwich BUFF* (ePrint **2025/1749**, 2025) attains the strongest NR
the impossibility results allow. **Crucially, our attribution-binding does not rely on NR:**

- We attribute to the **(signing key, decision-message)**, never to a signature *bitstring*. A
  re-signed-but-equivalent signature on the same `(m, pk)` attributes to the *same* key/decision — no
  mis-attribution.
- The tamper-evident log **dedups by the decision nonce** (modeled as `UniqueCommitPerNonce`), so a
  re-derived signature cannot drive a *second* actuation. Replay-injectivity (P3) comes from the
  protocol mechanism, not from NR of the primitive.

Hence even the theoretically-thorny NR question does not open a gap in our claim.

## 3. The adopted design rule (defense-in-depth; candidate sub-contribution)

Although ML-DSA already provides (a)+(b) natively, we make the dependency **explicit and robust** at
the application layer — this is the BUFF *transform* applied to the provenance record:

1. **Bind the asserter's public key into the signed payload and the log entry** (`sign(H(pk_A ‖ x))`
   in spirit; concretely: sign `x` and store `pk_A` in the committed record, and have the guard check
   the credited key equals the key bound in the record). This is what FIPS 204 does internally via
   `tr`; we mirror it at the record level so the *symbolic* model's exclusive-ownership assumption is
   sound and visible rather than hidden in the equational theory.
2. **Use the FIPS-204 context string** as a domain separator for the smart-home-actuation domain.
3. **Attribute to (key, decision), dedup by nonce** — as above.

`formal/tamarin/attribution_buff_fixed.spthy` machine-checks that rule #1 **restores**
attribution-binding (`EO_honest_signature_uniquely_credited` **verified**) *even under a deliberately
EO-failing primitive*. So our system's attribution claim is robust to the BUFF assumption: if ML-DSA's
exclusive ownership held today (it does, per 2025/900) **or** were weakened tomorrow, the
application-level binding carries the property.

## 4. Effect on the Task-2 P3 claim (the gate)

The Task-2 PQC model proves P3 under a signature theory that *assumes* DEO/MBS. Task 3 discharges that
assumption two ways: (i) **literature** — ML-DSA provides DEO/MBS (2025/900); (ii) **machine-checked
robustness** — even without it, the adopted binding transform restores P3 (`attribution_buff_fixed`).
Therefore P3 may now be recorded as **proven for ML-DSA** (no longer merely "under an optimistic
theory"), with the explicit caveat that the claim rests on SHAKE-256 collision resistance and on the
application-level pk-binding being implemented as specified.

**Recommendation: GO.** No blocking BUFF gap. No re-scoping of RQ2 needed. Carry the pk-binding design
rule into the Task-5 implementation and the eventual write-up as a stated requirement, and cite
2020/1525, 2025/900, 2023/1634, 2024/793 for the BUFF footing.

## References
- Cremers, Düzlü, Fiedler, Günther, Janson. *BUFF: Beyond UnForgeability Features.* IEEE S&P 2021. ePrint 2020/1525.
- *Exclusive Ownership of Fiat-Shamir Signatures: ML-DSA, SQIsign, LESS, and More.* ePrint 2025/900 (2025).
- Don, Fehr, Huang, Struck. *On the (In)Security of the BUFF Transform.* CRYPTO 2024. ePrint 2023/1634.
- *Hide-and-Seek and the Non-Resignability of the BUFF Transform.* TCC 2024. ePrint 2024/793.
- *Sandwich BUFF: Achieving Non-Resignability Using Iterative Hash Functions.* ePrint 2025/1749 (2025).
- Jackson, Cremers, Cohn-Gordon, Sasse. *Seems Legit: Automated Analysis of Subtle Attacks on Protocols that Use Signatures.* ACM CCS 2019. (Tamarin with/without-exclusive-ownership signature modeling — methodology for the sensitivity/fixed pair.)
- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard* (ML-DSA), 2024.
