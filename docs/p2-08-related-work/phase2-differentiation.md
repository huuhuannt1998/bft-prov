# Phase 2 — Related-Work Differentiation Table (Task 8)

Positions PQ-BFT-Prov against the nearest Phase-2 prior art. Pillars extend the Phase-1 four with the
BFT/quorum dimension. Honesty framing (dec_01KVWZ2RY2TDP7BQCPSKETY3RN): **"first verified realization +
systematization," NOT a conceptual first** — deVadoss already published quorum-gated actuation and the
correlated-fault observation; we do **not** claim those as novel.

Pillars:
- **Q-Gate** — a quorum of agents gates the actuation (BFT decision integrity).
- **PQC-Cert** — the quorum certificate is **post-quantum** (ML-DSA-signed votes).
- **Fusion** — the certificate is the **single** artifact = BFT-safety witness **and** attribution token
  (not two stapled mechanisms).
- **Verified** — **machine-checked** joint property (BFT-safety *and* quantum-attribution), composed.
- **Actuation** — terminates at a (smart-home) actuation event.

`●` full · `◐` partial · `○` absent.

| Work | Q-Gate | PQC-Cert | Fusion | Verified | Actuation |
|------|:--:|:--:|:--:|:--:|:--:|
| **deVadoss** (arXiv:2504.14668) — quorum-gated actuation + correlated-fault, **conceptual** | ● | ◐ | ◐ | ○ (not machine-checked) | ◐ |
| **CP-WBFT** (arXiv:2511.10400) — weighted BFT for LLMs, **text tasks** | ● | ○ | ○ | ○ | ○ |
| **Trusted MultiLLMN** (arXiv:2505.05103) — BFT consensus among LLMs, **text** | ● | ○ | ○ | ○ | ○ |
| **PQ-BFT blockchain** (Simple-IT arXiv:2606.14404 / QuantumShield-BC) — PQC + BFT for **ledgers** | ● | ● | ◐ (ledger, not agent-decision attribution) | ◐ (protocol, not the joint agent property) | ○ |
| **Pro2Guard** (arXiv:2508.00500) — single-agent runtime probabilistic safety (PMC) | ○ (single agent) | ○ | ○ | ◐ (probabilistic, single-agent) | ◐ |
| **CaMeL** — capability isolation, provable security on 77% of AgentDojo | ○ | ○ | ○ | ◐ (capability proof, no quorum/PQC) | ◐ |
| **PQ-BFT-Prov (this work)** | ● | ● | **●** | **●** (Tamarin J2 + Apalache J1, composed) | **◐ (emulated)** |

## The cell PQ-BFT-Prov occupies — honestly
No prior work holds **Q-Gate × PQC-Cert × Fusion × Verified** together:
- BFT-for-LLM works (CP-WBFT, MultiLLMN) operate on **text**, are **classical**, and have **no
  machine-checked** joint property and **no actuation**.
- PQ-BFT **blockchain** work has PQC+BFT but for **ledgers**, not LLM-agent decision→actuation
  attribution, and does not machine-check a *joint* agent property.
- deVadoss is the **conceptual** predecessor (quorum-gated actuation + correlated faults) — we cite it
  as prior art and explicitly **do not** claim that concept; our contribution is the **verified
  realization**: the post-quantum quorum certificate as the *single* artifact that is both the
  BFT-safety witness (Apalache J1) and the non-repudiable quantum-attribution token (Tamarin J2), with
  the composition argument as a first-class deliverable, plus the certificate-level BUFF analysis.

**Honest caveats:**
- **Actuation is emulated** (`◐`, M4-only Home Assistant virtual devices) — we do not claim physical
  CPS novelty; the contribution is carried by the verified joint property.
- **Decorrelation is a measured eval axis, not the headline** — correlated cross-model jailbreaks
  (Task 6) are reported as findings (including negative results), not assumed away. deVadoss already
  raised correlated faults; we **measure** them, not claim the observation.

## Not claimed as novel
Quorum-gated actuation (deVadoss); BFT-among-LLMs in the abstract (CP-WBFT/MultiLLMN); PQC+BFT in the
abstract (blockchain line); the correlated-fault observation; the symbolic quantum-adversary device;
physical actuation. Novelty is defended only at the **verified fusion** intersection. Re-check the 2026
preprint space before submission (trigger (e): a machine-checked BFT-for-LLM-actuation-with-PQC system).
