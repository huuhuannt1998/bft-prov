# Certificate-level BUFF Assessment — go/adjust memo (Phase 2, Task 4)

Mission `mis_01KVWZY3TK1WJHWD7P6AZV2F2G`, Task 4. Answers the novel coupled crypto+consensus
question: do the beyond-EUF-CMA / BUFF properties hold for the **aggregate quorum certificate**, not
just individual ML-DSA signatures? **Gates J2** (certificate attribution-binding) and is checkpoint
trigger (a). Seeded from the Phase-1 `attribution_buff_fixed.spthy` pk-binding transform, per PI.

**Bottom line: GO for the aggregate (concatenation) certificate.** Because the Phase-2 certificate is
a **concatenation-aggregate of independent ML-DSA signatures** — *not* a threshold/combined signature
— each vote keeps full single-signer BUFF (exclusive ownership + message-bound; Meyer–Struck–Weishäupl
ePrint 2025/900, λ-bit). The certificate-level attacks are then closed by **structural** checks in
`WellFormedQC`, which are **machine-checked** in `formal/tamarin/cert_attribution_pqc.spthy`. The
threshold-EO caveat (ePrint 2025/427) does **not** bite here; it would bite only for the **stretch-goal
threshold-signature** variant, which is correctly deferred.

---

## 1. The three certificate-level BUFF properties (beyond per-vote BUFF)

| # | Certificate attack | Closed by |
|---|--------------------|-----------|
| (a) | **Mix-and-match**: assemble a "valid" QC from votes for *different* `(actuation, view)` | each vote signs `⟨pk_i, act, v⟩`; `well_formed` requires all 2f+1 votes carry the **same** `(act, v)` |
| (b) | **Agent-set substitution / ballot stuffing**: re-attribute a QC to a different set, or pad with duplicates | `well_formed` requires **distinct** `pk_i`, all **authentic** (registered); each vote bound to its own `pk_i` |
| (c) | **Cross-view replay**: reuse votes/cert from view `v` to actuate in `v' ≠ v` | the **view `v` is bound into every signed vote**; `UniqueCert(act, v)` dedups commitment |

These are the certificate analogues of the single-signer BUFF features (exclusive ownership,
message-bound, non-resignability) lifted to the 2f+1 aggregate.

## 2. Why the aggregate keeps BUFF (and the threshold caveat does not bite)

- **Per-vote BUFF is inherited.** Every vote is an independent ML-DSA signature over `⟨pk_i, act, v⟩`.
  ML-DSA provides full-strength exclusive ownership + message-bound (2025/900, via `tr=H(pk)`/
  SHAKE-256), and we additionally bind `pk_i` and the context at the application layer (the Phase-1
  transform, machine-checked in `attribution_buff_fixed.spthy`). So no vote can be re-credited to a
  different key or re-bound to a different `(act, v)`.
- **The certificate's integrity is structural, not cryptographic-aggregation.** We do **not** combine
  the 2f+1 signatures into one object whose security would depend on an aggregate/threshold notion. The
  QC is the *set* of independent votes; its validity is the conjunction of (per-vote BUFF) ∧
  (`WellFormedQC` structural checks). Therefore the **ePrint 2025/427** result — that the EO hierarchy
  carries to **threshold** schemes only if they are also **robust** — does not apply: there is no
  threshold combination to lose EO through. (lit_01KVX3Q9V67JM4MKTEBKTMMHTX)
- **Stretch goal flagged.** A compact single-signature **threshold ML-DSA** certificate (TALUS / Mithril
  / Hermine) *would* re-open the 2025/427 question — the certificate would need threshold-robustness to
  retain exclusive ownership. That is explicitly a stretch goal / possible second paper, **not** Phase-2
  core (dec_01KVWZ2RY2TDP7BQCPSKETY3RN). If pursued, certificate-BUFF must be re-proven under robustness.

## 3. Machine-checked evidence (`formal/tamarin/cert_attribution_{pqc,classical}.spthy`)

Core case N=4, f=1, quorum=3; quantum adversary (ML-DSA retained) controlling one Byzantine agent
(its key leaked). All runs ≤ 0.5 s, **0 wellformedness warnings**.

| Lemma | PQC (ML-DSA) | Classical (Shor leaks all keys) |
|-------|--------------|---------------------------------|
| `J2_honest_quorum_backing` — every actuation backed by ≥ 2 **distinct-key honest** votes | **verified** | **falsified** (Shor forges the certificate) |
| `J2_injective` — no cert replay to a second actuation | verified | verified |
| forgery (actuation with no honest backing) | **unreachable** | **reachable** (`forgery_reachable_classical` verified) |

`J2_honest_quorum_backing` is the certificate-level lift of Phase-1 P3: with ≤ f Byzantine, a 2f+1
certificate necessarily carries ≥ f+1 = 2 honest votes, so no f-bounded adversary can forge a
certificate or re-attribute an actuation — **provided** the structural checks (a)–(c) above are
enforced, which `well_formed` does and the model proves. (Debugging note: getting here required
bounding Byzantine registrations to f=1 — an early unbounded version let the adversary forge a full
certificate — and keying the honest-quorum lemma on **public keys**, not reused agent names; both are
recorded in `cert_RESULTS.md`.)

## 4. Recommendation

**GO.** Certificate-level BUFF holds for the aggregate certificate under the stated structural checks;
no re-scope of J2. Checkpoint trigger (a) **not** met. Carry forward: (i) the `WellFormedQC` checks are
load-bearing — they must be exactly mirrored in the consensus impl (`consensus/certificate.py`,
already done) and in the Apalache `ValidVote` abstraction (Task 3) and reconciled in the composition
note (Task 5); (ii) if threshold ML-DSA is later adopted for a compact certificate, re-open this memo
under the 2025/427 robustness requirement.

## References
- ePrint 2025/900 (Meyer, Struck, Weishäupl) — ML-DSA λ-bit exclusive ownership. [lit_01KVX2E3DC62R2MN5V8SCZJMNX]
- ePrint 2020/1525 (Cremers et al.) — BUFF definitions. [lit_01KVX2E819YJTCQGTK7GCJWHDF]
- ePrint 2025/427 — exclusive ownership for threshold signatures requires robustness. [lit_01KVX3Q9V67JM4MKTEBKTMMHTX]
- Jackson et al., CCS 2019 — with/without-EO signature modeling. [lit_01KVX2EJ6SXD05MFC5PX2V19ZK]
