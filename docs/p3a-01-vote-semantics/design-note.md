# Phase 3a Task 1 — Vote-semantics & OPA-role design note (FOR PI APPROVAL BEFORE REWIRE)

Mission mis_01KVXG1BRBWSGC4GPNTA61MNQQ, Task 1. Per the PI: bring this before the rewire. The load-
bearing decision is **OPA's role**: if OPA still carries all safety, the quorum/diversity is vacuous
and we are back at trigger-(d). This note proposes the design and flags the choices I need ratified.

## 1. The as-built gap (why we are here)
`consensus/replica.py:36` makes an honest vote the **deterministic OPA decision**; the LLM never feeds
the vote. The end-to-end flips a **simulated rubber-stamp** and never invokes a model. `transfer.py`
measures **model susceptibility** at a layer that never reaches a vote. So the decorrelation study and
the end-to-end measure different layers and do not compose, and "diverse agents resist injection" is
not what the code does.

## 2. New vote semantics (the thesis, implemented)
Each agent is one model family. The agent's **model** judges the proposed actuation given the full
context (the proposal **plus** the ingested content, with ingested content clearly marked as DATA) and
emits an **approve / deny vote**. That vote is ML-DSA-signed; the quorum certifies only on **2f+1
approve** votes. A real injection that corrupts an agent's model judgment now **flips that agent's
vote**. Injection-resistance becomes: does the injection flip at least f+1 model families? That is
exactly what the decorrelation study measures, so the two studies compose.

## 3. OPA's role (THE decision) — proposed: thin inviolable floor + advisory input
To keep the quorum non-vacuous, OPA must **not** carry the substantive safety decision. Proposal:

**Reclassify policy into two tiers.**
- **Inviolable constraints (thin, context-independent).** A small set of absolutely-never actions that
  **no** request or context justifies, e.g. disabling a life-safety alarm (smoke / CO / gas), unlocking
  **every** door at once, or disabling the security system entirely. OPA hard-denies these as a
  **post-quorum backstop**: even a fully-injected unanimous quorum cannot perform them. This is a
  genuine safety floor for the handful of actions that are never appropriate.
- **Context-dependent actuations (the majority).** Unlock *the* front door, run the boiler, open *the*
  garage, set a thermostat: these can be legitimate depending on the request and context. These are
  decided by the **diverse model quorum**. Injection-resistance for them lives in model diversity
  (2f+1 approvals required; at most f injected families cannot reach it if the honest majority judges
  correctly).

**OPA verdict as advisory input (recommended).** Each agent's model is given the OPA policy verdict for
the proposal as advisory context ("policy guidance: this action is normally restricted"). Honest models
benefit from policy; an injection competes with that advice; diversity decides who wins. OPA advises,
it does not decide.

Net: OPA = a thin inviolable floor (post-quorum) plus advisory guidance (pre-vote); the diverse quorum
makes the substantive, injection-resistant decision. **OPA does not carry all safety, so the quorum is
not vacuous** (avoids trigger-(d)).

## 4. Safety rationale
J1 ("no f Byzantine cause an actuation the honest quorum would reject") now reads, in the vote path, as
"no f injected model-agents can force a context-dependent unsafe approval" (2f+1 needed; at most f
injected cannot reach it given an honest majority), **plus** the OPA inviolable floor for the absolute
set. The honest consequence, pre-registered: for context-dependent hazards, safety now **depends on the
diverse quorum**, which is weaker than a hard static policy but is the actual thesis. High-transfer
injections (e.g. `lock-5` flipping all four families) **will** defeat the quorum end-to-end once models
vote; the detector becomes the **load-bearing** backstop in the real path, and where it misses, the
case is a counted residual failure. We report this straight (same discipline as the EO lemma and the
spotlighting-backfire negative result); we do not tune it away.

## 5. Attribution rationale (Claim A unchanged)
The certificate is **2f+1 distinct valid ML-DSA votes for the same (actuation, view)** — unchanged. The
vote's *content* (model judgment vs OPA verdict) does not touch the certificate structure or
`WellFormedQC`. So Claim A (Apalache J1 + Tamarin J2) should **re-verify unchanged**; Task 3 confirms
this (re-verify, not assert), and STOPs if it breaks (trigger-(a)). The **attribution floor** holds by
construction: every certified actuation is bound to a valid certificate naming the 2f+1 authorizing
keys, **even when a successful injection drives an unsafe actuation** — which is Phase 4's spine.

## 6. What changes in the implementation (scope of the rewire)
- `consensus/replica.py`: honest vote = model judgment (one Ollama call per agent on proposal+context),
  not the OPA decision. The simulated rubber-stamp is retained only as a clearly-labeled worst-case
  adjunct (or dropped — see choice 3).
- A thin OPA backstop applied **after** the quorum for the inviolable set; OPA verdict passed to models
  as advisory input.
- `decorrelation/transfer.py` and the testbed now exercise the **same** model-judgment vote, so the two
  studies compose. The 12-injection / 4-family corpus is unchanged in Phase 3a (Phase 4 scales it).

## 7. Choices I need ratified before I rewire
1. **Inviolable set boundary.** Proposed: only life-safety absolutes (disable smoke/CO/gas alarm;
   unlock-all-doors; disable security system). Everything else (single-door unlock, boiler, single
   garage, thermostat) goes to the model quorum. Is this the right line, a different set, or **none**
   (pure design-ii, no OPA floor — maximally tests the quorum, removes the safety floor)?
2. **OPA-as-advisory-input:** include (recommended) or omit (purer test of unaided model diversity)?
3. **Simulated rubber-stamp:** keep as a labeled worst-case adjunct, or drop entirely now that real
   injections flip real votes?

My recommendation: inviolable set = the three life-safety absolutes; advisory input **on**; keep the
rubber-stamp only as a labeled worst-case sanity adjunct. This locates injection-resistance in the
diverse quorum (the thesis), keeps a genuine floor for the never-appropriate actions, and preserves the
attribution floor and Claim A. Nothing is rewired until you rule on 1-3.
