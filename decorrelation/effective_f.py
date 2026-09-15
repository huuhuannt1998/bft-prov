"""
Correlation-aware sizing input: turn the measured transfer matrix (Task 6) into an EFFECTIVE-f per
injection and a quorum-sizing recommendation. effective-f is treated as a MEASURED quantity (PI
refinement #4), not an assumed 1.

For each injection, the worst-case correlated cluster = the set of families it flips simultaneously.
A family-diversity quorum requiring `d` distinct families BLOCKS an injection by sizing iff the
injection's cross-family flip count c < d (the flipped cluster cannot cover the required distinct
families on its own; honest families vote correctly and refuse). If c >= d, sizing cannot block it —
detection (sanitization) must, else it is a residual failure.
"""
from __future__ import annotations
import json
import os

HERE = os.path.dirname(__file__)


def load_matrix(path: str | None = None) -> dict:
    path = path or os.path.join(HERE, "matrix.json")
    with open(path) as f:
        return json.load(f)  # family -> {cid: bool}


def per_injection_flips(matrix: dict) -> dict[str, int]:
    families = list(matrix)
    cids = list(next(iter(matrix.values())).keys())
    return {c: sum(1 for fam in families if matrix[fam][c]) for c in cids}


def summary(matrix: dict) -> dict:
    families = list(matrix)
    nf = len(families)
    flips = per_injection_flips(matrix)
    effective_f = max(flips.values())            # largest correlated cross-family cluster observed
    # A diversity quorum requiring d distinct families blocks injection c iff flips[c] < d.
    # With nf families, the max d we can require while keeping a Byzantine bound is nf (then f=0) —
    # to keep f>=1 we need d <= nf-1. Report what each feasible d would block.
    blockable = {}
    for d in range(2, nf + 1):
        blockable[d] = [c for c, k in flips.items() if k < d]
    return {
        "families": families, "n_families": nf, "flips": flips,
        "effective_f_families": effective_f,
        "blockable_by_diversity_d": blockable,
        # to size around effective_f by diversity alone you need d > effective_f, i.e. n_families > effective_f
        "diversity_sizing_feasible": (nf > effective_f),
        "sizing_shortfall": max(0, (effective_f + 1) - nf),
    }


if __name__ == "__main__":
    m = load_matrix()
    s = summary(m)
    print(f"families={s['families']}")
    print(f"per-injection cross-family flips: {s['flips']}")
    print(f"effective-f (max correlated cluster) = {s['effective_f_families']} of {s['n_families']} families")
    print(f"diversity-sizing feasible with available families? {s['diversity_sizing_feasible']} "
          f"(shortfall={s['sizing_shortfall']} more families needed to size around the worst injection)")
    for d, cs in s["blockable_by_diversity_d"].items():
        print(f"  require d={d} distinct families -> blocks {len(cs)}/{len(s['flips'])} injections by sizing: {sorted(cs)}")
