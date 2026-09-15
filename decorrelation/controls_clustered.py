#!/usr/bin/env python3
"""Two-way cluster bootstrap for the matched benign controls.

The pooled control rate in controls_analysis.json is a Wilson interval over every
agent x control x repetition decision. That treats three repetitions of one control on one
agent as three independent observations, and it pools the original 18 controls (3 reps) with
the 36 expanded controls (1 rep) at different weights per control. Both inflate precision.

Here each (agent, control) cell contributes its mean over repetitions exactly once, and the
bootstrap resamples agents and controls independently, matching the two-way scheme used for
the pairwise dependence intervals. Writes a NEW file; no existing artifact is modified.
"""
import json
import os
import glob
import collections
import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))
SEED = 20260801
N_BOOT = 2000

# Kind is read off the control id prefix; the expanded corpus encodes it there by construction.
KIND = {
    "quoted": "quoted attack text",
    "historical": "historical log",
    "negated": "explicitly forbids the action",
    "warning": "security warning",
    "documentation": "API documentation",
    "lookalike": "legitimate look-alike",
    "instruction": "benign instruction",
}


def load_cells():
    """cells[(agent, control)] = mean approval over that cell's repetitions."""
    cells = {}
    reps_seen = collections.Counter()

    # Original 18 controls, 3 repetitions, one file per agent.
    for f in sorted(glob.glob(os.path.join(ROOT, "rq1", "*.json"))):
        d = json.load(open(f))
        agent = f"{d['tag']}|{d['defense']}"
        ctl = d.get("controls") or {}
        for cid, v in ctl.items():
            if isinstance(v, list):
                vals = [1.0 if x else 0.0 for x in v]
            elif isinstance(v, dict):
                vals = [1.0 if x else 0.0 for x in v.values()]
            else:
                vals = [1.0 if v else 0.0]
            if not vals:
                continue
            cells[(agent, cid)] = float(np.mean(vals))
            reps_seen[len(vals)] += 1

    # Expanded 36 controls, 1 repetition, one combined file.
    exp = json.load(open(os.path.join(ROOT, "controls_expanded.json")))
    for agent, cell in exp["cells"].items():
        for cid, v in cell["raw"].items():
            cells[(agent, cid)] = 1.0 if v else 0.0
            reps_seen[1] += 1

    return cells, reps_seen


def two_way_boot(cells, agents, controls, rng):
    """Resample agents and controls independently; return the resampled cell mean."""
    a_idx = rng.integers(0, len(agents), len(agents))
    c_idx = rng.integers(0, len(controls), len(controls))
    acc = []
    for ai in a_idx:
        a = agents[ai]
        for ci in c_idx:
            v = cells.get((a, controls[ci]))
            if v is not None:
                acc.append(v)
    return float(np.mean(acc)) if acc else np.nan


def summarize(cells, controls, label, rng):
    agents = sorted({a for a, _ in cells})
    controls = [c for c in controls if any((a, c) in cells for a in agents)]
    point = float(np.mean([cells[(a, c)] for a in agents for c in controls if (a, c) in cells]))
    draws = np.array([two_way_boot(cells, agents, controls, rng) for _ in range(N_BOOT)])
    draws = draws[~np.isnan(draws)]
    lo, hi = np.percentile(draws, [2.5, 97.5])
    return {
        "label": label,
        "n_agents": len(agents),
        "n_controls": len(controls),
        "n_cells": sum(1 for a in agents for c in controls if (a, c) in cells),
        "rate": point,
        "ci": [float(lo), float(hi)],
    }


def main():
    rng = np.random.default_rng(SEED)
    cells, reps_seen = load_cells()
    all_controls = sorted({c for _, c in cells})

    # The design is unbalanced across sources: the 18 original controls were run on all 78
    # configurations, the 36 expanded controls only on the 65-agent deployable pool. The
    # balanced subset is the 65 agents that carry all 54, and that is what we report.
    per_agent = collections.Counter(a for a, _ in cells)
    full = {a for a, n in per_agent.items() if n == len(all_controls)}
    balanced = {k: v for k, v in cells.items() if k[0] in full}

    out = {
        "meta": {
            "seed": SEED,
            "n_boot": N_BOOT,
            "cells_union": len(cells),
            "cells_balanced": len(balanced),
            "agents_union": len(per_agent),
            "agents_balanced": len(full),
            "note": "each (agent, control) cell contributes once -- the original 18 controls are "
                    "stored already collapsed over their 3 repetitions, the 36 expanded controls "
                    "were run at 1 repetition -- and the bootstrap resamples agents and controls "
                    "independently. Headline is the balanced 65-agent x 54-control design; the "
                    "unbalanced union is reported alongside it.",
        },
        "pooled": summarize(balanced, all_controls, "all matched controls (balanced)", rng),
        "pooled_union": summarize(cells, all_controls, "all matched controls (union)", rng),
        "by_kind": [],
    }

    for prefix, label in KIND.items():
        sel = [c for c in all_controls if c.startswith(f"ctl-{prefix}")]
        if sel:
            out["by_kind"].append(summarize(balanced, sel, label, rng))
    out["by_kind"].sort(key=lambda r: -r["rate"])

    path = os.path.join(ROOT, "controls_clustered.json")
    json.dump(out, open(path, "w"), indent=1)

    for key in ("pooled", "pooled_union"):
        p = out[key]
        print(f"{p['label']:<36} {p['rate']*100:5.1f}% [{p['ci'][0]*100:.1f}, {p['ci'][1]*100:.1f}]  "
              f"({p['n_agents']} agents x {p['n_controls']} controls, {p['n_cells']} cells)")
    for r in out["by_kind"]:
        print(f"   {r['label']:<32} {r['rate']*100:5.1f}% "
              f"[{r['ci'][0]*100:4.1f}, {r['ci'][1]*100:5.1f}]  n_ctl={r['n_controls']}")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
