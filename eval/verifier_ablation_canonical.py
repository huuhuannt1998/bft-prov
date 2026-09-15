#!/usr/bin/env python3
"""Quorum / verifier / combined ablation, computed on the CANONICAL member sets.

eval/verifier_ablation.py draws its own 100 member sets with a fresh RNG, so its numbers come from a
different draw than decorrelation/canonical_quorums.py, which is what the paper's quorum table reports.
The two disagreed (HOM-3of5 quorum-only 23.7% there against 19.2% in the paper), which makes the shipped
artifact look like it contradicts the manuscript when it is only a different sample.

This script removes the discrepancy by reusing the canonical member sets verbatim instead of redrawing.
The verifier half is unchanged: one fixed, declared deployment context, decided by action class, never
seeing injected content. Writes a NEW file; the original artifact is left in place as the record of the
earlier draw.

Usage: PYTHONPATH=. python3 eval/verifier_ablation_canonical.py
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from decorrelation.analyze_quorum import (load_agents, pb_tail, stratified_split,  # noqa: E402
                                          category_of)
from decorrelation.corpus_main import build_corpus  # noqa: E402

CANON = os.path.join(ROOT, "decorrelation", "canonical_quorums.json")
PRIOR = os.path.join(ROOT, "eval", "verifier_ablation.json")
OUT = os.path.join(ROOT, "eval", "verifier_ablation_canonical.json")

# The rows the paper's ablation table reports.
SPEC = [("HOM-3of5", "homogeneous", 5, 3),
        ("JD-3of5", "joint-diverse", 5, 3),
        ("JD-4of7", "joint-diverse", 7, 4),
        ("JD-5of7", "joint-diverse", 7, 5)]


def main() -> None:
    canon = json.load(open(CANON))
    # The verifier's per-action decisions are a deterministic function of the policy bundle and the
    # declared context, so they are reused from the prior run rather than re-queried through OPA.
    prior = json.load(open(PRIOR))
    dec = {tuple(k.split(" ", 1)): v for k, v in prior["action_decisions"].items()}

    agents, _raw, items = load_agents()
    cases = {c.cid: c for c in build_corpus()}
    cats = category_of(items["inj"])
    _, test_idx = stratified_split(items["inj"], cats)

    permit = np.array([1.0 if dec[(cases[c].device, cases[c].command)] == "permit" else 0.0
                       for c in items["inj"]])
    pmt = permit[test_idx][None, :]

    # canonical_quorums.json stores member keys as "tag|defense" strings; agents is keyed by Agent.
    by_key = {a.key: a for a in agents}

    rows = []
    for qid, strat, n, q in SPEC:
        sets = canon["member_sets"][f"{strat}|{n}"]
        P = np.stack([np.stack([agents[by_key[a]]["inj"][test_idx] for a in Q], 1) for Q in sets])
        q_x = np.stack([pb_tail(P[s], q) for s in range(len(sets))])
        rows.append({"id": qid, "strategy": strat, "N": n, "q": q, "n_member_sets": len(sets),
                     "quorum_only": float(q_x.mean()),
                     "verifier_only": float(pmt.mean()),
                     "combined": float((q_x * pmt).mean())})

    json.dump({"meta": {"source": "canonical member sets from decorrelation/canonical_quorums.json",
                        "seed": canon["meta"]["seed"],
                        "n_test_payloads": int(len(test_idx)),
                        "note": "supersedes eval/verifier_ablation.json, which drew its own member "
                                "sets and therefore reported a different sample of the same design"},
               "action_decisions": prior["action_decisions"],
               "context": prior["context"],
               "ablation": rows}, open(OUT, "w"), indent=1)

    canon_rows = {r["id"]: r for r in canon["rows"]}
    print(f"{'id':<10}{'quorum':>9}{'verifier':>10}{'combined':>10}   agrees with canonical_quorums?")
    for r in rows:
        c = canon_rows[r["id"]]
        ok = (abs(r["quorum_only"] - c["asr"]) < 5e-4
              and abs(r["combined"] - c["combined_with_verifier"]) < 5e-4)
        print(f"{r['id']:<10}{r['quorum_only']*100:8.1f}%{r['verifier_only']*100:9.1f}%"
              f"{r['combined']*100:9.1f}%   {'YES' if ok else 'NO'}"
              f"  (canonical {c['asr']*100:.1f} / {c['combined_with_verifier']*100:.1f})")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
