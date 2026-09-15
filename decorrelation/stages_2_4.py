#!/usr/bin/env python3
"""Stages 2-4 of research_design_detailed.md, run under .planning/PREREGISTRATION.md.

No new inference: everything reuses the existing 65 x 342 vote matrix. Member-set draws are the
power lever, and draws are free, so this whole arm is analysis rather than measurement.

  Stage 2  confirmatory selection result   -> O1 (erosion), O2 (necessity)
  Stage 3  necessity ladder l1..l4         -> how much each increment of knowledge buys
  Stage 4  mechanism                       -> O4 (one-dimensionality), O5 (family structure),
                                              O3 (agreement vs marginal-strength channel), O6 (probing)

Every parameter is read from the frozen preregistration values below; none is chosen after seeing a
result. Writes decorrelation/stages_2_4.json.

Usage: PYTHONPATH=. python3 decorrelation/stages_2_4.py
"""
from __future__ import annotations

import itertools
import json
import os
import sys

import numpy as np
from scipy.stats import spearmanr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from decorrelation.analyze_quorum import load_agents, FAMILY  # noqa: E402

# ---- frozen by .planning/PREREGISTRATION.md ------------------------------------------------
SEED = 20260801
DRAWS = 2000
Q, N = 3, 5
K_FRAC = 0.10
N_PROBE = 50
N_BOOT = 2000
RHO_ONEDIM = 0.95      # O4 threshold
RHO_STRUCTURE = 0.60   # O5 threshold
# --------------------------------------------------------------------------------------------


def load():
    agents, _, _ = load_agents()
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda x: x.key)
    bykey = {a.key: agents[a]["inj"] for a in agents}
    meta = {a.key: (FAMILY.get(a.tag), a.defense) for a in pool}
    P = np.vstack([agents[a]["inj"] for a in pool])
    return P, [a.key for a in pool], bykey, meta, agents, pool


def draw_sets(keys, meta, rule, n, rng):
    """Fresh member sets under a named composition rule."""
    out = []
    guard = 0
    while len(out) < n and guard < n * 200:
        guard += 1
        if rule == "homogeneous":
            out.append([keys[rng.integers(0, len(keys))]] * N)
            continue
        sel, fams, defs = [], set(), set()
        for i in rng.permutation(len(keys)):
            k = keys[i]
            f, d = meta[k]
            if rule == "joint-diverse" and (f in fams or d in defs):
                continue
            if rule == "family-diverse" and f in fams:
                continue
            if rule == "defense-diverse" and d in defs:
                continue
            sel.append(k)
            fams.add(f)
            defs.add(d)
            if len(sel) == N:
                break
        if len(sel) == N:
            out.append(sel)
    return out


def outcomes(sets, bykey, q=Q):
    V = np.array([np.vstack([bykey[x] for x in s]) for s in sets])
    return V, (V.sum(axis=1) >= q).astype(float)


def boot_ci(v, rng, n_boot=N_BOOT):
    bs = [v[rng.integers(0, len(v), len(v))].mean() for _ in range(n_boot)]
    return float(np.mean(v)), [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]


def stage2(Vj, Oj, Vh, Oh, P, rng, n_pay, level="l3"):
    """Fair-contrast erosion. l3 obtained by probing, never assumed."""
    l1 = P.mean(axis=0)
    vals, acc = [], []
    for t in range(len(Oj)):
        probes = rng.choice(n_pay, N_PROBE, replace=False)
        rest = np.setdiff1d(np.arange(n_pay), probes)
        dev, test = rest[: len(rest) // 2], rest[len(rest) // 2:]
        k = max(5, int(len(dev) * K_FRAC))
        if level == "l3":
            gj = int(np.argmin((Oj[:, probes] != Oj[t][probes]).sum(axis=1)))
            gh = int(np.argmin((Oh[:, probes] != Oh[t][probes]).sum(axis=1)))
            acc.append(((Oj[gj][test] == Oj[t][test]).mean()
                        + (Oh[gh][test] == Oh[t][test]).mean()) / 2)
            sj, sh = Vj[gj].mean(axis=0), Vh[gh].mean(axis=0)
        elif level == "l2":                      # the rule, not the realized set
            sj, sh = Oj.mean(axis=0), Oh.mean(axis=0)
        elif level == "l1":                      # per-agent marginals only
            sj = sh = l1
        elif level == "l4":                      # upper bound: the true set
            sj, sh = Vj[t].mean(axis=0), Vh[t].mean(axis=0)
        selJ = dev[np.argsort(-sj[dev])[:k]]
        selH = dev[np.argsort(-sh[dev])[:k]]
        vals.append((Oh[t][test].mean() - Oj[t][test].mean())
                    - (Oh[t][selH].mean() - Oj[t][selJ].mean()))
    m, ci = boot_ci(np.array(vals), rng)
    return m, ci, (float(np.mean(acc)) if acc else None)


def stage4_onedim(keys, bykey, meta, P, rng):
    """O4/O5: is every rule's aggregate ranking a monotone transform of one scalar?"""
    u = P.mean(axis=0)
    res = {}
    for rule in ("homogeneous", "family-diverse", "defense-diverse", "joint-diverse"):
        sets = draw_sets(keys, meta, rule, 400, rng)
        _, O = outcomes(sets, bykey)
        res[rule] = float(spearmanr(u, O.mean(axis=0))[0])
    fam = {}
    for k in keys:
        fam.setdefault(meta[k][0], []).append(bykey[k])
    fam = {k: np.vstack(v).mean(axis=0) for k, v in fam.items() if len(v) >= 3}
    pairs = {f"{i}|{j}": float(spearmanr(fam[i], fam[j])[0])
             for i, j in itertools.combinations(sorted(fam), 2)}
    return res, pairs


def stage4_channel(Vj, Oj, P, rng, n_pay):
    """O3: does selection raise agreement-given-a-hit, or only marginal strength?"""
    l1 = P.mean(axis=0)
    m_sh, g_sh = [], []
    for t in range(min(600, len(Oj))):
        rest = np.arange(n_pay)
        dev, test = rest[: n_pay // 2], rest[n_pay // 2:]
        k = max(5, int(len(dev) * K_FRAC))
        sel = dev[np.argsort(-Vj[t].mean(axis=0)[dev])[:k]]
        base_s = Vj[t][:, test].sum(axis=0)
        sel_s = Vj[t][:, sel].sum(axis=0)
        m_sh.append(Vj[t][:, sel].mean() - Vj[t][:, test].mean())
        gb = (base_s >= Q).sum() / max(1, (base_s >= 1).sum())
        gs = (sel_s >= Q).sum() / max(1, (sel_s >= 1).sum())
        g_sh.append(gs - gb)
    return boot_ci(np.array(m_sh), rng), boot_ci(np.array(g_sh), rng)


def main() -> None:
    rng = np.random.default_rng(SEED)
    P, keys, bykey, meta, agents, pool = load()
    n_pay = P.shape[1]
    out = {"preregistered": True, "draws": DRAWS, "seed": SEED, "n_agents": len(keys),
           "n_payloads": n_pay}
    print(f"substrate: {len(keys)} agents x {n_pay} payloads, {DRAWS} draws, no new inference\n")

    jd = draw_sets(keys, meta, "joint-diverse", DRAWS, rng)
    hom = draw_sets(keys, meta, "homogeneous", DRAWS, rng)
    Vj, Oj = outcomes(jd, bykey)
    Vh, Oh = outcomes(hom, bykey)
    D0 = float((Oh.mean(axis=1) - Oj.mean(axis=1)).mean())
    out["D0_pp"] = D0 * 100
    print(f"STAGE 2 — confirmatory selection result   (dividend D0 = {D0*100:.2f} pp)")

    m, ci, acc = stage2(Vj, Oj, Vh, Oh, P, rng, n_pay, "l3")
    out["O1"] = {"E_pp": m * 100, "ci_pp": [c * 100 for c in ci]}
    out["O6"] = {"probe_accuracy": acc, "n_probe": N_PROBE}
    sev = ("S5" if ci[1] < 0 else "S4" if ci[0] <= 0 else
           "S1" if (D0 - m) <= 0 else "S2" if m >= D0 / 2 else "S3")
    out["O1"]["severity"] = sev
    print(f"  O1 erosion (l3, probed)  E = {m*100:+.2f} pp  CI [{ci[0]*100:+.2f}, {ci[1]*100:+.2f}]"
          f"   -> {sev}")
    print(f"  O6 probe accuracy        {acc:.4f} at {N_PROBE} probes"
          f"   -> {'PASS' if acc >= 0.95 else 'FAIL'}")

    print("\nSTAGE 3 — necessity ladder")
    ladder = {}
    for lv in ("l1", "l2", "l3", "l4"):
        mm, cc, _ = stage2(Vj, Oj, Vh, Oh, P, rng, n_pay, lv)
        ladder[lv] = {"E_pp": mm * 100, "ci_pp": [c * 100 for c in cc]}
        tag = "  <- upper bound, not a threat claim" if lv == "l4" else ""
        print(f"  {lv}  E = {mm*100:+6.2f} pp  CI [{cc[0]*100:+6.2f}, {cc[1]*100:+6.2f}]{tag}")
    out["stage3_ladder"] = ladder
    chi = 1 if (ladder["l3"]["ci_pp"][0] > 0 and ladder["l1"]["E_pp"] <= 0) else 0
    out["O2"] = {"chi": chi}
    print(f"  O2 chi = {chi}  ({'composition knowledge necessary' if chi else 'l1 suffices / no effect to attribute'})")

    print("\nSTAGE 4 — mechanism")
    onedim, fampairs = stage4_onedim(keys, bykey, meta, P, rng)
    out["O4"] = {"rho_by_rule": onedim, "threshold": RHO_ONEDIM,
                 "pass": all(v >= RHO_ONEDIM for v in onedim.values())}
    for r, v in onedim.items():
        print(f"  O4 rho(u, {r:<16}) = {v:.4f}  {'ok' if v >= RHO_ONEDIM else 'BELOW THRESHOLD'}")
    lo = min(fampairs.values())
    out["O5"] = {"min_cross_family_rho": lo, "pass": lo <= RHO_STRUCTURE, "pairs": fampairs}
    print(f"  O5 min cross-family rho = {lo:.3f}  -> "
          f"{'structure exists below the aggregate' if lo <= RHO_STRUCTURE else 'no exploitable structure'}")
    (mm, mci), (gm, gci) = stage4_channel(Vj, Oj, P, rng, n_pay)
    out["O3"] = {"m_shift": mm, "m_ci": mci, "g_shift": gm, "g_ci": gci,
                 "pass": gci[0] > 0}
    print(f"  O3 marginal-strength shift m = {mm*100:+.2f} pp  CI [{mci[0]*100:+.2f}, {mci[1]*100:+.2f}]")
    print(f"     agreement-given-a-hit  g = {gm*100:+.2f} pp  CI [{gci[0]*100:+.2f}, {gci[1]*100:+.2f}]"
          f"   -> {'agreement channel' if gci[0] > 0 else 'no agreement channel'}")

    # --- two findings the design did not anticipate, added after the first run ------------
    print("\nSTAGE 4b — deployment variance and dividend precision (exploratory)")
    spread = {}
    for rule in ("homogeneous", "family-diverse", "defense-diverse", "joint-diverse"):
        _, O = outcomes(draw_sets(keys, meta, rule, DRAWS, rng), bykey)
        per = O.mean(axis=1) * 100
        spread[rule] = {"mean": float(per.mean()), "sd": float(per.std()),
                        "p95": float(np.percentile(per, 95)), "max": float(per.max())}
        print(f"  {rule:<17} mean {per.mean():5.1f}%  sd {per.std():5.1f} pp  "
              f"p95 {np.percentile(per,95):5.1f}%  worst {per.max():5.1f}%")
    h, j = spread["homogeneous"], spread["joint-diverse"]
    spread["variance_ratio_hom_over_jd"] = (h["sd"] ** 2) / (j["sd"] ** 2)
    print(f"  a homogeneous deployment is a lottery over one agent: {spread['variance_ratio_hom_over_jd']:.1f}x "
          f"the variance of a jointly diverse one")
    out["stage4b_deployment_spread"] = spread

    prec = {}
    for nd in (200, DRAWS):
        ests = []
        for _ in range(120):
            _, Oh_ = outcomes(draw_sets(keys, meta, "homogeneous", nd, rng), bykey)
            _, Oj_ = outcomes(draw_sets(keys, meta, "joint-diverse", nd, rng), bykey)
            ests.append((Oh_.mean() - Oj_.mean()) * 100)
        e = np.array(ests)
        prec[nd] = {"mean": float(e.mean()), "sd": float(e.std()),
                    "ci": [float(np.percentile(e, 2.5)), float(np.percentile(e, 97.5))]}
        print(f"  D0 measured at {nd:>4} draws: {e.mean():5.2f} pp, sd {e.std():4.2f}, "
              f"95% range [{np.percentile(e,2.5):.2f}, {np.percentile(e,97.5):.2f}]")
    out["stage4b_dividend_precision"] = prec

    path = os.path.join(ROOT, "decorrelation", "stages_2_4.json")
    json.dump(out, open(path, "w"), indent=1)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
