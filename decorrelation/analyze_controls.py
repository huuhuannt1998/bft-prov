"""Expanded-control false-approval analysis (reviewer 4.3).

Combines the original 18 minimally contrastive controls with the 36 expanded controls, whose ingested
text resembles an injection without carrying authorization. Correct decision on every control is DENY, so
any approval is a false approval. Reports pooled and per-defense rates with Wilson intervals, plus a
breakdown by control kind, which is what says whether a defense is fooled by the mere APPEARANCE of an
instruction rather than by an actual one.

Usage: PYTHONPATH=. python -m decorrelation.analyze_controls
"""
from __future__ import annotations

import collections
import json
import math
import os

from decorrelation.analyze_quorum import load_agents
from decorrelation.controls_expanded import CONTROLS

HERE = os.path.dirname(__file__)
DEFENSES = ["provenance", "struq", "hierarchy", "spotlight", "known_answer"]


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return p * 100, (c - m) / d * 100, (c + m) / d * 100


def main() -> None:
    exp = json.load(open(os.path.join(HERE, "controls_expanded.json")))["cells"]
    agents, raw, items = load_agents()
    kind = {c.cid: c.kind for c in CONTROLS}

    print(f"expanded controls: {len(CONTROLS)} cases x {len(exp)} agents, 1 repetition")
    print(f"original controls: {len(items['ctrl'])} cases x 3 repetitions\n")

    print(f"{'defense':<14}{'original 18':>26}{'expanded 36':>26}{'combined 54':>26}")
    rows = {}
    for d in DEFENSES:
        ok = [a for a in agents if a.defense == d]
        k_o = int(sum(raw[a]["ctrl"].sum() for a in ok))
        n_o = int(sum(raw[a]["ctrl"].size for a in ok))
        cells = [v for k, v in exp.items() if k.split("|")[1] == d]
        k_e = sum(sum(v["raw"].values()) for v in cells)
        n_e = sum(len(v["raw"]) for v in cells)
        fo, lo_o, hi_o = wilson(k_o, n_o)
        fe, lo_e, hi_e = wilson(k_e, n_e)
        fc, lo_c, hi_c = wilson(k_o + k_e, n_o + n_e)
        rows[d] = {"orig": [fo, lo_o, hi_o, k_o, n_o], "exp": [fe, lo_e, hi_e, k_e, n_e],
                   "comb": [fc, lo_c, hi_c, k_o + k_e, n_o + n_e]}
        print(f"{d:<14}{fo:8.1f} [{lo_o:4.1f},{hi_o:5.1f}]{fe:11.1f} [{lo_e:4.1f},{hi_e:5.1f}]"
              f"{fc:11.1f} [{lo_c:4.1f},{hi_c:5.1f}]")

    K_o = sum(int(sum(raw[a]["ctrl"].sum() for a in agents if a.defense == d)) for d in DEFENSES)
    N_o = sum(int(sum(raw[a]["ctrl"].size for a in agents if a.defense == d)) for d in DEFENSES)
    K_e = sum(sum(v["raw"].values()) for v in exp.values())
    N_e = sum(len(v["raw"]) for v in exp.values())
    p, lo, hi = wilson(K_o + K_e, N_o + N_e)
    pe, loe, hie = wilson(K_e, N_e)
    print(f"\npooled over the deployable pool:")
    print(f"  original 18 : {wilson(K_o,N_o)[0]:.1f}% [{wilson(K_o,N_o)[1]:.1f}, {wilson(K_o,N_o)[2]:.1f}]  n={N_o}")
    print(f"  expanded 36 : {pe:.1f}% [{loe:.1f}, {hie:.1f}]  n={N_e}")
    print(f"  combined 54 : {p:.1f}% [{lo:.1f}, {hi:.1f}]  n={N_o+N_e}")

    by = collections.defaultdict(lambda: [0, 0])
    for v in exp.values():
        for cid, approved in v["raw"].items():
            b = by[kind[cid]]
            b[0] += int(approved); b[1] += 1
    print(f"\nfalse approval by control kind (expanded set):")
    for k in sorted(by, key=lambda k: -by[k][0] / by[k][1]):
        a, n = by[k]
        f, l, h = wilson(a, n)
        print(f"  {k:<14} {f:5.1f}% [{l:4.1f},{h:5.1f}]  ({a}/{n})")

    out = os.path.join(HERE, "controls_analysis.json")
    with open(out, "w") as f:
        json.dump({"per_defense": rows,
                   "pooled": {"original": wilson(K_o, N_o), "expanded": [pe, loe, hie],
                              "combined": [p, lo, hi], "n_original": N_o, "n_expanded": N_e},
                   "by_kind": {k: {"approved": v[0], "n": v[1], "rate": v[0] / v[1]}
                               for k, v in by.items()}}, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
