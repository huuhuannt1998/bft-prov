#!/usr/bin/env python3
"""Does the dependence survive on a sub-pool anyone would actually deploy?

The 65-agent deployable pool still contains configurations no operator would ship: several sit above 70%
attack success on their own. A reviewer is entitled to ask whether the jointly-diverse excess is carried
by agents that approve nearly everything, in which case it would say little about a competent deployment.

This re-runs the paper's own estimator, decorrelation.analyze_quorum.dependence_agent_cluster, on
progressively stricter sub-pools. Nothing about the statistic changes; only pool membership does. The
unfiltered row must reproduce the published table, and is printed alongside it as a check.

Usage: PYTHONPATH=. python3 decorrelation/competent_subpool.py
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from decorrelation.analyze_quorum import load_agents, dependence_agent_cluster  # noqa: E402

N_BOOT = 1000
CEILINGS = [None, 0.50, 0.30, 0.20]      # None = the full 65-agent deployable pool
REPORT = ["family-diverse, defense-diverse", "family-diverse, same defense",
          "same family, defense-diverse"]
PUBLISHED = os.path.join(ROOT, "decorrelation", "dep_agentcluster.json")


def main() -> None:
    agents, _raw, _items = load_agents()
    pool = [a for a in agents if a.defense != "none"]
    asr = {a: float(agents[a]["inj"].mean()) for a in pool}

    out = {"meta": {"n_boot": N_BOOT,
                    "estimator": "decorrelation.analyze_quorum.dependence_agent_cluster",
                    "note": "the paper's two-way agent x payload cluster bootstrap, re-run on sub-pools "
                            "filtered by per-agent attack success; only pool membership changes"},
           "levels": []}

    for ceil in CEILINGS:
        keep = sorted([a for a in pool if ceil is None or asr[a] < ceil], key=lambda x: x.key)
        if len(keep) < 6:
            continue
        table = dependence_agent_cluster(agents, keep, n_boot=N_BOOT)
        out["levels"].append({
            "ceiling": ceil,
            "n_agents": len(keep),
            "pool_asr_mean": float(np.mean([asr[a] for a in keep])),
            "pool_asr_max": float(max(asr[a] for a in keep)),
            "categories": {c: {k: v for k, v in table[c].items()
                               if k in ("lift", "lift_ci", "joint", "indep", "n_pairs")}
                           for c in REPORT if c in table},
        })

    path = os.path.join(ROOT, "decorrelation", "competent_subpool.json")
    json.dump(out, open(path, "w"), indent=1)

    pub = json.load(open(PUBLISHED))
    key = "family-diverse, defense-diverse"
    full = out["levels"][0]["categories"][key]
    agree = (abs(full["lift"] - pub[key]["lift"]) < 5e-3
             and abs(full["lift_ci"][0] - pub[key]["lift_ci"][0]) < 5e-2)
    print(f"check: unfiltered jointly diverse = {full['lift']:.3f} "
          f"[{full['lift_ci'][0]:.3f}, {full['lift_ci'][1]:.3f}]; published "
          f"{pub[key]['lift']:.3f} [{pub[key]['lift_ci'][0]:.3f}, {pub[key]['lift_ci'][1]:.3f}] "
          f"-> {'REPRODUCES' if agree else 'DOES NOT MATCH'}\n")

    print(f"{'ceiling':>9}{'agents':>8}{'max ASR':>10}{'mean ASR':>10}   jointly diverse lift [95% CI]")
    for lv in out["levels"]:
        c = lv["categories"].get(key)
        cap = "none" if lv["ceiling"] is None else f"<{lv['ceiling']*100:.0f}%"
        print(f"{cap:>9}{lv['n_agents']:>8}{lv['pool_asr_max']*100:>9.1f}%"
              f"{lv['pool_asr_mean']*100:>9.1f}%   "
              f"{c['lift']:.3f} [{c['lift_ci'][0]:.3f}, {c['lift_ci'][1]:.3f}]  ({c['n_pairs']} pairs)")
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
