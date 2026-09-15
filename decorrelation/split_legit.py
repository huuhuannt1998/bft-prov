"""P0-C: honest legitimate-task split, and LAAR in place of "utility" (USENIX revision).

Reviewer objection this closes: the best-security-utility (BSU) composition rule selected members using
ALL legitimate tasks, so its reported 100% acceptance was in-sample. The manuscript disclosed this, but
disclosure is not a fix.

Here the legitimate corpus is split, stratified by target action, into a development half the selection
rule may see and a held-out half it may not. Data-driven rules select on development attacks AND
development legitimate tasks only; every reported number is then computed on the held-out halves. The
sampled member sets are otherwise identical to the canonical draw, so the only thing that changes is
what the selection rule was allowed to look at.

Metric naming: what is measured is whether the quorum approves a benign requested action, not whether a
user's task ultimately succeeded. It is therefore reported as LAAR (legitimate action acceptance rate),
not as "utility".

Usage: PYTHONPATH=. python -m decorrelation.split_legit
"""
from __future__ import annotations

import json
import os
import random

import numpy as np

from decorrelation.analyze_quorum import (STRATEGIES, DATA_DRIVEN, load_agents, member_sets, pb_tail,
                                          stratified_split, category_of)

HERE = os.path.dirname(__file__)
SEED = 20260801
K_SETS = 200
N_BOOT = 1000


def legit_split(items, seed=SEED):
    """Stratify the legitimate corpus by target action so both halves cover the same action space."""
    from decorrelation.corpus_tdsc import build_tdsc_corpus
    cases = {c.cid: c for c in build_tdsc_corpus()}
    key = [f"{cases[c].device}|{cases[c].command}" if c in cases else "unknown" for c in items["legit"]]
    rng = random.Random(seed)
    dev, hold = [], []
    by = {}
    for i, k in enumerate(key):
        by.setdefault(k, []).append(i)
    for k in sorted(by):
        idx = by[k][:]
        rng.shuffle(idx)
        cut = len(idx) // 2
        dev += idx[:cut]
        hold += idx[cut:]
    return np.array(sorted(dev)), np.array(sorted(hold))


def main() -> None:
    agents, raw, items = load_agents()
    cats = category_of(items["inj"])
    train_idx, test_idx = stratified_split(items["inj"], cats)
    dev_l, hold_l = legit_split(items)
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)
    byname = {a.key: a for a in agents}
    print(f"attacks: {len(train_idx)} dev / {len(test_idx)} held out")
    print(f"legitimate: {len(dev_l)} dev / {len(hold_l)} held out  (stratified by target action)\n")

    # Selection rules may see development attacks and development legitimate tasks ONLY.
    # member_sets() consumes agents[a]["legit"] for the utility term, so hand it a dev-only view.
    dev_view = {a: {"inj": agents[a]["inj"], "legit": agents[a]["legit"][dev_l]} for a in agents}

    rng = random.Random(SEED)
    boot = np.random.default_rng(SEED)
    rows = []
    for strat in STRATEGIES:
        for n, q in ((3, 2), (5, 3), (7, 4), (7, 5)):
            sets = member_sets(dev_view, pool, strat, n, K_SETS, rng, train_idx)
            keys = [[a.key for a in S] for S in sets]
            Pi = np.stack([np.stack([agents[byname[k]]["inj"][test_idx] for k in S], 1) for S in keys])
            Pl = np.stack([np.stack([agents[byname[k]]["legit"][hold_l] for k in S], 1) for S in keys])
            asr_x = np.stack([pb_tail(Pi[s], q) for s in range(len(sets))])
            laar_x = np.stack([pb_tail(Pl[s], q) for s in range(len(sets))])
            nS = len(sets)
            ba, bl = [], []
            for _ in range(N_BOOT):
                ss = boot.integers(0, nS, nS)
                ba.append(float(asr_x[np.ix_(ss, boot.integers(0, asr_x.shape[1], asr_x.shape[1]))].mean()))
                bl.append(float(laar_x[np.ix_(ss, boot.integers(0, laar_x.shape[1], laar_x.shape[1]))].mean()))
            rows.append({"composition": strat, "N": n, "q": q, "data_driven": strat in DATA_DRIVEN,
                         "n_member_sets": nS,
                         "asr": float(asr_x.mean()),
                         "asr_ci": [float(np.percentile(ba, 2.5)), float(np.percentile(ba, 97.5))],
                         "laar": float(laar_x.mean()),
                         "laar_ci": [float(np.percentile(bl, 2.5)), float(np.percentile(bl, 97.5))]})

    out = {"meta": {"seed": SEED, "k_sets": K_SETS, "n_boot": N_BOOT,
                    "n_dev_attacks": int(len(train_idx)), "n_heldout_attacks": int(len(test_idx)),
                    "n_dev_legit": int(len(dev_l)), "n_heldout_legit": int(len(hold_l)),
                    "metric": "LAAR = legitimate action acceptance rate on held-out benign requests",
                    "note": "data-driven selection sees development attacks and development legitimate "
                            "tasks only; all reported values are held-out on both axes"},
           "rows": rows}

    print(f"{'composition':<26}{'q-of-N':>8}{'ASR [95% CI]':>22}{'LAAR [95% CI]':>24}  sel")
    for r in rows:
        print(f"{r['composition']:<26}{r['q']}-of-{r['N']:<4}"
              f"{r['asr']*100:8.1f} [{r['asr_ci'][0]*100:5.1f},{r['asr_ci'][1]*100:5.1f}]"
              f"{r['laar']*100:10.1f} [{r['laar_ci'][0]*100:5.1f},{r['laar_ci'][1]*100:5.1f}]"
              f"  {'data-driven' if r['data_driven'] else ''}")
    path = os.path.join(HERE, "split_legit.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
