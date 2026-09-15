"""Canonical quorum results: ONE member-set sample, evaluated under every condition.

Reviewer issue 3.1. The static, verifier-combined, and adaptive analyses each drew their own member
sets (200, 100, and 150 respectively), so the same labelled configuration reported different attack
success in different tables. That is a reporting defect, not a modelling one, and this script removes it:
member sets are sampled ONCE per (composition, N), assigned a stable identifier, persisted, and then
scored under all three conditions.

Every number in the manuscript's quorum tables, adaptive paragraph, abstract, and conclusion is read
from the file this produces.

Definitions used throughout, stated because reviewer issues 3.2 and 6.1 turn on them.

  Per-payload rate. For agent i and payload x, $p_i(x)$ is the fraction of the three independent model
  invocations that approved. Quorum outcomes are computed from these rates by a Poisson-binomial
  recursion, so a q-of-N result is the probability that at least q of N independently drawn invocations
  approve, not a single observed vote tally.

  Homogeneous replication is therefore COUNTERFACTUAL: an N-member homogeneous quorum reuses one
  configuration's $p_i(x)$ N times, modelling N independent invocations of that configuration on the
  same payload. Only three invocations per (agent, payload) were actually run, so N>3 homogeneous
  quorums are simulated from the estimated rate rather than observed directly. Diverse quorums combine
  distinct agents and are simulated the same way.

  Pooled independence prediction. $\\bar p_i \\bar p_j$ style: each member fails independently at its
  POOLED MARGINAL rate over payloads. A ratio above one therefore reflects shared-input dependence
  induced by variation in payload difficulty, not conditional dependence given a payload.

Usage: PYTHONPATH=. python -m decorrelation.canonical_quorums
"""
from __future__ import annotations

import json
import os
import random

import numpy as np

from decorrelation.analyze_quorum import (STRATEGIES, load_agents, member_sets, pb_tail,
                                          stratified_split, category_of)

HERE = os.path.dirname(__file__)
SEED = 20260801
K_SETS = 200
N_BOOT = 1000

# (identifier, composition rule, N, q). One row per quorum instance the manuscript names.
SPEC = [
    ("HOM-2of3", "homogeneous",     3, 2), ("HOM-3of5", "homogeneous",     5, 3),
    ("HOM-1of5", "homogeneous",     5, 1), ("HOM-5of5", "homogeneous",     5, 5),
    ("HOM-4of7", "homogeneous",     7, 4),
    ("FD-2of3",  "family-diverse",  3, 2), ("FD-3of5",  "family-diverse",  5, 3),
    ("FD-5of7",  "family-diverse",  7, 5), ("FD-7of7",  "family-diverse",  7, 7),
    ("DD-3of5",  "defense-diverse", 5, 3),
    ("JD-2of3",  "joint-diverse",   3, 2), ("JD-3of5",  "joint-diverse",   5, 3),
    ("JD-4of7",  "joint-diverse",   7, 4), ("JD-5of7",  "joint-diverse",   7, 5),
    ("RND-3of5", "random",          5, 3), ("RND-4of7", "random",          7, 4),
    ("BSU-3of5", "best-security-utility", 5, 3),
]


def jeffreys_upper(k: int, n: int, conf: float = 0.95) -> float:
    """Upper confidence bound for a proportion; finite even when k = 0."""
    from scipy.stats import beta
    return float(beta.ppf(conf, k + 0.5, n - k + 0.5)) if n else 1.0


def main() -> None:
    agents, raw, items = load_agents()
    cats = category_of(items["inj"])
    train_idx, test_idx = stratified_split(items["inj"], cats)
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)

    # ---- one member-set sample, reused everywhere
    rng = random.Random(SEED)
    chosen: dict[str, list[list[str]]] = {}
    for qid, strat, n, q in SPEC:
        key = f"{strat}|{n}"
        if key not in chosen:
            sets = member_sets(agents, pool, strat, n, K_SETS, rng, train_idx)
            chosen[key] = [[a.key for a in Q] for Q in sets]
    # The supplementary grid covers every composition rule at every threshold. It is drawn AFTER the
    # SPEC keys so the RNG stream reaching those keys is unchanged and the main-paper identifiers keep
    # exactly the member sets they had; the grid then reuses those same sets wherever they overlap.
    for strat in STRATEGIES:
        for n in (3, 5, 7):
            key = f"{strat}|{n}"
            if key not in chosen:
                sets = member_sets(agents, pool, strat, n, K_SETS, rng, train_idx)
                chosen[key] = [[a.key for a in Q] for Q in sets]
    byname = {a.key: a for a in agents}

    # ---- adaptive rates on the same agents
    ad = json.load(open(os.path.join(HERE, "adaptive_pool.json")))
    pids = sorted(next(iter(ad["cells"].values()))["raw"].keys())
    A = {k: np.array([np.mean(v["raw"][p]) for p in pids]) for k, v in ad["cells"].items()}

    # ---- verifier permit mask per payload (fixed away/evening context)
    vb = json.load(open(os.path.join(os.path.dirname(HERE), "eval", "verifier_ablation.json")))
    from decorrelation.corpus_tdsc import build_tdsc_corpus
    cases = {c.cid: c for c in build_tdsc_corpus()}
    permit = np.array([1.0 if vb["action_decisions"][f"{cases[c].device} {cases[c].command}"] == "permit"
                       else 0.0 for c in items["inj"]])

    nX, nL = len(test_idx), len(items["legit"])
    boot = np.random.default_rng(SEED)
    bx = [boot.integers(0, nX, nX) for _ in range(N_BOOT)]
    bl = [boot.integers(0, nL, nL) for _ in range(N_BOOT)]

    rows = []
    for qid, strat, n, q in SPEC:
        sets = chosen[f"{strat}|{n}"]
        Pi = np.stack([np.stack([agents[byname[k]]["inj"][test_idx] for k in Q], 1) for Q in sets])
        Pl = np.stack([np.stack([agents[byname[k]]["legit"] for k in Q], 1) for Q in sets])
        marg = Pi.mean(axis=1)
        asr_x = np.stack([pb_tail(Pi[s], q) for s in range(len(sets))])          # [k, X]
        util_x = np.stack([pb_tail(Pl[s], q) for s in range(len(sets))])
        pred_s = np.array([pb_tail(marg[s][None, :], q)[0] for s in range(len(sets))])
        comb_x = asr_x * permit[test_idx][None, :]
        Pa = np.stack([np.stack([A[k] for k in Q], 1) for Q in sets]) if all(k in A for Q in sets for k in Q) else None
        adapt = float(np.stack([pb_tail(Pa[s], q) for s in range(len(sets))]).mean()) if Pa is not None else None

        # Bootstrap resamples payloads AND member sets jointly, so the intervals carry
        # composition-selection uncertainty as well as payload uncertainty.
        nS = len(sets)
        b_asr, b_pred, b_util, b_ratio, b_comb = [], [], [], [], []
        for i in range(N_BOOT):
            ii, ll = bx[i], bl[i]
            ss = boot.integers(0, nS, nS)
            a_ = float(asr_x[np.ix_(ss, ii)].mean())
            p_ = float(pb_tail(Pi[:, ii, :].mean(axis=1)[ss], q).mean())
            b_asr.append(a_); b_pred.append(p_)
            b_util.append(float(util_x[np.ix_(ss, ll)].mean()))
            b_ratio.append(a_ / max(p_, 1e-12))
            b_comb.append(float(comb_x[np.ix_(ss, ii)].mean()))
        ci = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]

        # exact counts behind a zero/near-zero row, for a finite upper bound
        approx_fail = int(round(asr_x.mean() * nX))
        rows.append({
            "id": qid, "composition": strat, "N": n, "q": q, "n_member_sets": len(sets),
            "n_test_payloads": nX, "n_legit_tasks": nL,
            "asr": float(asr_x.mean()), "asr_ci": ci(b_asr),
            "asr_upper95_if_zero": jeffreys_upper(approx_fail, nX),
            "pred": float(pred_s.mean()), "pred_ci": ci(b_pred),
            "ratio": float(asr_x.mean() / max(pred_s.mean(), 1e-12)), "ratio_ci": ci(b_ratio),
            "utility": float(util_x.mean()), "utility_ci": ci(b_util),
            "combined_with_verifier": float(comb_x.mean()), "combined_ci": ci(b_comb),
            "adaptive_asr": adapt,
            "members_example": sets[0],
        })

    # ---- full grid: every composition rule at every threshold, same canonical member sets.
    # This is what Supplementary Table S3 prints, so main and supplementary cannot disagree.
    grid = []
    for strat in STRATEGIES:
        for n in (3, 5, 7):
            sets = chosen[f"{strat}|{n}"]
            Pi = np.stack([np.stack([agents[byname[k]]["inj"][test_idx] for k in Q], 1) for Q in sets])
            Pl = np.stack([np.stack([agents[byname[k]]["legit"] for k in Q], 1) for Q in sets])
            marg = Pi.mean(axis=1)
            for q in range(1, n + 1):
                a_ = float(np.stack([pb_tail(Pi[s], q) for s in range(len(sets))]).mean())
                p_ = float(np.array([pb_tail(marg[s][None, :], q)[0] for s in range(len(sets))]).mean())
                u_ = float(np.stack([pb_tail(Pl[s], q) for s in range(len(sets))]).mean())
                grid.append({"composition": strat, "N": n, "q": q, "n_member_sets": len(sets),
                             "asr": a_, "pred": p_, "ratio": a_ / max(p_, 1e-12), "utility": u_})

    out = os.path.join(HERE, "canonical_quorums.json")
    with open(out, "w") as f:
        json.dump({"meta": {"seed": SEED, "k_sets": K_SETS, "n_boot": N_BOOT,
                            "n_train_payloads": int(len(train_idx)), "n_test_payloads": nX,
                            "n_legit": nL, "pool_size": len(pool), "n_adaptive_payloads": len(pids),
                            "bootstrap_units": "payloads and member sets jointly"},
                   "rows": rows, "grid": grid, "member_sets": chosen}, f, indent=2)

    print(f"{'ID':<10}{'ASR [95% CI]':>22}{'Pred':>8}{'Ratio [95% CI]':>20}{'Util [95% CI]':>21}"
          f"{'Comb':>7}{'Adapt':>7}")
    for r in rows:
        print(f"{r['id']:<10}{r['asr']*100:6.1f} [{r['asr_ci'][0]*100:4.1f},{r['asr_ci'][1]*100:5.1f}]"
              f"{r['pred']*100:8.1f}{r['ratio']:8.2f} [{r['ratio_ci'][0]:.2f},{r['ratio_ci'][1]:.2f}]"
              f"{r['utility']*100:9.1f} [{r['utility_ci'][0]*100:4.1f},{r['utility_ci'][1]*100:5.1f}]"
              f"{r['combined_with_verifier']*100:7.1f}"
              f"{(r['adaptive_asr']*100 if r['adaptive_asr'] is not None else float('nan')):7.1f}")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
