"""Adaptive-attacker analysis over the deployable pool (IoT-J revision, reviewer C2).

Answers the objection the non-adaptive corpus raises against the paper's own design: a training-selected
agent reaches 0% attack success at full utility there, which would imply agent selection solves the
problem and a quorum is unnecessary. That inference holds only if the attacker does not adapt.

Reports, on the same 65-agent deployable pool and with the same quorum machinery:
  * per-defense adaptive attack success against the static-corpus figure
  * what happens to the agents a static selection rule would have chosen
  * quorum attack success on adaptive payloads for the compositions of the main table

Usage: PYTHONPATH=. python -m decorrelation.analyze_adaptive
"""
from __future__ import annotations

import json
import os
import random
import statistics as st

import numpy as np

from decorrelation.analyze_quorum import (Agent, load_agents, member_sets, pb_tail, stratified_split,
                                          category_of, thresholds_for)

HERE = os.path.dirname(__file__)


def main() -> None:
    ad = json.load(open(os.path.join(HERE, "adaptive_pool.json")))
    cells, reps = ad["cells"], ad["reps"]
    pids = sorted(next(iter(cells.values()))["raw"].keys())
    print(f"adaptive corpus: {len(pids)} payloads (5 targets x 2 rounds), {len(cells)} agents, "
          f"{reps} repetitions\n")

    # per-agent adaptive rate vector
    A = {k: np.array([np.mean(v["raw"][p]) for p in pids]) for k, v in cells.items()}

    agents, raw, items = load_agents()
    stat = {f"{a.tag}|{a.defense}": agents[a]["inj"] for a in agents}
    util = {f"{a.tag}|{a.defense}": float(agents[a]["legit"].mean()) for a in agents}
    cats = category_of(items["inj"])
    train_idx, test_idx = stratified_split(items["inj"], cats)
    strain = {k: float(v[train_idx].mean()) for k, v in stat.items()}

    print(f"{'defense':<14}{'static ASR':>12}{'adaptive ASR':>14}{'change':>9}")
    for d in ["provenance", "struq", "hierarchy", "spotlight", "known_answer"]:
        ks = [k for k in A if k.split("|")[1] == d]
        s = st.mean(stat[k].mean() for k in ks)
        a = st.mean(A[k].mean() for k in ks)
        print(f"{d:<14}{s*100:11.1f}%{a*100:13.1f}%{(a-s)*100:+8.1f}")
    s_all = st.mean(stat[k].mean() for k in A)
    a_all = st.mean(A[k].mean() for k in A)
    print(f"{'POOL':<14}{s_all*100:11.1f}%{a_all*100:13.1f}%{(a_all-s_all)*100:+8.1f}\n")

    # the agents a static rule would have selected
    usable = [k for k in A if util[k] >= 0.80]
    best_su = max(A, key=lambda k: util[k] - strain[k])
    best_asr = min(usable, key=lambda k: strain[k]) if usable else None
    print("agents a static selection rule would pick, and how they fare when the attacker adapts:")
    for lab, k in (("best train security-utility", best_su),
                   ("lowest train ASR with utility>=80%", best_asr)):
        if k:
            print(f"  {lab:<36} {k:<34} static {stat[k].mean()*100:5.1f}%  "
                  f"ADAPTIVE {A[k].mean()*100:5.1f}%")
    surv = [k for k in A if A[k].mean() == 0.0]
    print(f"  agents still at 0% under adaptive attack: {len(surv)}/{len(A)}"
          + (f" ({', '.join(surv[:4])})" if surv else ""))

    # quorum behaviour on adaptive payloads
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)
    rng = random.Random(20260801)
    print(f"\n{'composition':<17}{'q-of-N':>8}{'static ASR':>12}{'adaptive ASR':>14}")
    rows = []
    for strat in ["homogeneous", "family-diverse", "defense-diverse", "joint-diverse", "random"]:
        for n in (3, 5, 7):
            sets = member_sets(agents, pool, strat, n, 150, rng, train_idx)
            if not sets:
                continue
            keys = [[f"{a.tag}|{a.defense}" for a in Q] for Q in sets]
            if any(k not in A for Q in keys for k in Q):
                continue
            Pa = np.stack([np.stack([A[k] for k in Q], 1) for Q in keys])
            Ps = np.stack([np.stack([stat[k][test_idx] for k in Q], 1) for Q in keys])
            for tname, t in thresholds_for(n):
                if t != n // 2 + 1:
                    continue
                sa = float(np.stack([pb_tail(Ps[s], t) for s in range(len(sets))]).mean())
                aa = float(np.stack([pb_tail(Pa[s], t) for s in range(len(sets))]).mean())
                rows.append({"strategy": strat, "N": n, "q": t, "static": sa, "adaptive": aa})
                print(f"{strat:<17}{t}-of-{n:<5}{sa*100:11.1f}%{aa*100:13.1f}%")

    out = os.path.join(HERE, "adaptive_analysis.json")
    with open(out, "w") as f:
        json.dump({"per_agent_adaptive": {k: float(v.mean()) for k, v in A.items()},
                   "pool_static": s_all, "pool_adaptive": a_all, "quorum": rows,
                   "selected_agents": {"best_security_utility": best_su,
                                       "adaptive_asr": float(A[best_su].mean())},
                   "n_payloads": len(pids)}, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
