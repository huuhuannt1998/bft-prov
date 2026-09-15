#!/usr/bin/env python3
"""Stage 6: per-request composition randomisation (ALG-7). Built, and gated closed.

research_design_detailed.md orders the stages so the gate precedes the intervention it licenses:
randomisation hides the realized member set, so it defends against an attacker for whom that
knowledge has value. Stages 2-4 found composition knowledge buys at most a marginal, non-robust
advantage, which means running this today would evaluate a defense against an attack that does not
work -- and would produce a number that looks like a defense result and is not one.

So this file refuses to run until Stage 5 exits E1. The refusal is the point: the code exists so the
work is ready the moment the gate opens, and the guard exists so having the code does not become a
reason to use it.

No new inference when it does run: randomisation is a different way of drawing member sets from the
vote matrix already collected.

Usage: PYTHONPATH=. python3 -m decorrelation.stage6_intervention
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))

from decorrelation.stages_2_4 import (  # noqa: E402
    SEED, DRAWS, Q, K_FRAC, N_PROBE, load, draw_sets, outcomes, boot_ci,
)

GATE_FILE = os.path.join(HERE, "stage5_full_result.json")


def gate_open() -> tuple[bool, str]:
    """Stage 6 runs only on exit E1: authoring broke one-dimensionality AND composition
    knowledge acquired value. Anything else and the intervention has nothing to defend."""
    screen = os.path.join(HERE, "stage5_screen_result.json")
    if not os.path.exists(GATE_FILE):
        if os.path.exists(screen):
            r = json.load(open(screen))
            if r.get("exit"):
                return False, (f"Stage 5 exited {r['exit']} at the screen; the full arm was never "
                               f"authorised, so composition knowledge never acquired value")
        return False, "Stage 5 has not run; no stage5_full_result.json"
    r = json.load(open(GATE_FILE))
    exit_code = r.get("exit")
    if exit_code != "E1":
        return False, f"Stage 5 exited {exit_code or 'unresolved'}, not E1"
    return True, "Stage 5 exited E1"


def run(rng):
    """ALG-7 against a fixed-composition control, both scored under the fair contrast.

    Fixed arm:      the attacker probes, infers the deployed set, and targets it.
    Randomised arm: the member set is redrawn per request, so the set the attacker inferred is
                    not the set that decides. The attacker keeps its budget and its probes.
    """
    P, keys, bykey, meta, agents, pool = load()
    n_pay = P.shape[1]
    jd = draw_sets(keys, meta, "joint-diverse", DRAWS, rng)
    hom = draw_sets(keys, meta, "homogeneous", DRAWS, rng)
    Vj, Oj = outcomes(jd, bykey)
    Vh, Oh = outcomes(hom, bykey)

    fixed, rand = [], []
    for t in range(DRAWS):
        probes = rng.choice(n_pay, N_PROBE, replace=False)
        rest = np.setdiff1d(np.arange(n_pay), probes)
        dev, test = rest[: len(rest) // 2], rest[len(rest) // 2:]
        k = max(5, int(len(dev) * K_FRAC))
        gj = int(np.argmin((Oj[:, probes] != Oj[t][probes]).sum(axis=1)))
        gh = int(np.argmin((Oh[:, probes] != Oh[t][probes]).sum(axis=1)))
        selJ = dev[np.argsort(-Vj[gj].mean(axis=0)[dev])[:k]]
        selH = dev[np.argsort(-Vh[gh].mean(axis=0)[dev])[:k]]
        D0 = Oh[t][test].mean() - Oj[t][test].mean()
        fixed.append(D0 - (Oh[t][selH].mean() - Oj[t][selJ].mean()))
        # randomised: a different draw decides each request
        r = int(rng.integers(0, DRAWS))
        rand.append((Oh[r][test].mean() - Oj[r][test].mean())
                    - (Oh[r][selH].mean() - Oj[r][selJ].mean()))
    mf, cf = boot_ci(np.array(fixed), rng)
    mr, cr = boot_ci(np.array(rand), rng)
    return {"fixed": {"E_pp": mf * 100, "ci_pp": [c * 100 for c in cf]},
            "randomised": {"E_pp": mr * 100, "ci_pp": [c * 100 for c in cr]},
            "O6_pass": bool(cr[0] <= 0 <= cr[1]),
            "cost_note": "per-request draws forfeit warm per-member caching; on a memory-bound host "
                         "that is the real price and must be measured, not projected"}


def main() -> None:
    ok, why = gate_open()
    if not ok:
        print("Stage 6 is gated closed.")
        print(f"  reason: {why}")
        print("\n  research_design_detailed.md 13.2 orders the gate before the intervention:")
        print("  randomisation hides the realized member set, so it only defends against an")
        print("  attacker for whom that knowledge has value. Stages 2-4 measured that value as")
        print("  marginal and non-robust, so running this now would evaluate a defense against an")
        print("  attack that does not work.")
        print("\n  This file is complete and will run unchanged the moment Stage 5 exits E1.")
        raise SystemExit(0)

    rng = np.random.default_rng(SEED)
    res = run(rng)
    print(f"  fixed composition   E = {res['fixed']['E_pp']:+.2f} pp "
          f"[{res['fixed']['ci_pp'][0]:+.2f}, {res['fixed']['ci_pp'][1]:+.2f}]")
    print(f"  randomised          E = {res['randomised']['E_pp']:+.2f} pp "
          f"[{res['randomised']['ci_pp'][0]:+.2f}, {res['randomised']['ci_pp'][1]:+.2f}]")
    print(f"  O6 (erosion removed): {'PASS' if res['O6_pass'] else 'fail'}")
    path = os.path.join(HERE, "stage6_intervention.json")
    json.dump(res, open(path, "w"), indent=1)
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
