"""P0-B: observed q-of-N quorum tallies, not Poisson-binomial simulations (earlier revision).

Reviewer objection this closes: the manuscript's quorum numbers are computed by a Poisson-binomial
recursion over per-payload rates p_i(x), so they are SIMULATED outcomes rather than observed quorum
executions. For a security claim about what a deployed quorum does, an observed tally is stronger.

Every (agent, payload) cell was run three times, so for a member set of DISTINCT agents we can form a
genuine tally: take repetition r from every member, count approvals, apply the threshold. That is a real
q-of-N execution over votes that were actually produced. Three repetitions give three independent
executions per (set, payload); we report all three and their mean.

Homogeneous sets are excluded from the observed arm and stay labelled counterfactual: a homogeneous
N-member set needs N independent invocations of ONE configuration and only three were run, so N>3 cannot
be observed. This is the honest boundary and the paper states it rather than hiding it behind a model.

Usage: PYTHONPATH=. python -m decorrelation.empirical_quorum
"""
from __future__ import annotations

import json
import os

import numpy as np

from decorrelation.analyze_quorum import load_agents, pb_tail, stratified_split, category_of

HERE = os.path.dirname(__file__)
SEED = 20260801
N_BOOT = 1000


def main() -> None:
    agents, raw, items = load_agents()
    cats = category_of(items["inj"])
    _, test_idx = stratified_split(items["inj"], cats)
    canon = json.load(open(os.path.join(HERE, "canonical_quorums.json")))
    member_sets = canon["member_sets"]
    byname = {a.key: a for a in agents}
    rng = np.random.default_rng(SEED)

    rows = []
    for spec in canon["rows"]:
        qid, strat, N, q = spec["id"], spec["composition"], spec["N"], spec["q"]
        sets = member_sets[f"{strat}|{N}"]
        observed = strat != "homogeneous"      # homogeneous needs N invocations of one config
        rec = {"id": qid, "composition": strat, "N": N, "q": q,
               "analytical_asr": spec["asr"], "analytical_ci": spec["asr_ci"],
               "n_member_sets": len(sets), "observed": observed}

        if observed:
            # [set, member, payload, rep] -> tally per (set, payload, rep)
            V = np.stack([np.stack([raw[byname[k]]["inj"][test_idx] for k in S]) for S in sets])
            approvals = (V >= 0.5).sum(axis=1)                     # [set, payload, rep]
            hit = (approvals >= q).astype(float)                   # a real q-of-N outcome
            per_rep = hit.mean(axis=(0, 1))                        # one ASR per repetition
            emp = float(hit.mean())
            nS, nX = hit.shape[0], hit.shape[1]
            bs = [float(hit[np.ix_(rng.integers(0, nS, nS), rng.integers(0, nX, nX))].mean())
                  for _ in range(N_BOOT)]
            rec.update({"empirical_asr": emp,
                        "empirical_ci": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))],
                        "per_repetition_asr": [float(x) for x in per_rep],
                        "abs_diff_vs_analytical": emp - spec["asr"]})
        rows.append(rec)

    obs = [r for r in rows if r["observed"]]
    diffs = np.array([r["abs_diff_vs_analytical"] for r in obs])
    out = {"meta": {"seed": SEED, "n_boot": N_BOOT, "n_test_payloads": int(len(test_idx)),
                    "repetitions": 3,
                    "note": "observed arm uses repetition-matched tallies over distinct agents; "
                            "homogeneous compositions remain analytical and are labelled counterfactual"},
           "rows": rows,
           "agreement": {"n_observed": len(obs),
                         "mean_abs_diff_pp": float(np.abs(diffs).mean() * 100),
                         "max_abs_diff_pp": float(np.abs(diffs).max() * 100)}}

    print(f"{'ID':<10}{'obs':>5}{'empirical [95% CI]':>26}{'analytical':>12}{'diff pp':>9}  per-rep")
    for r in rows:
        if r["observed"]:
            pr = ",".join(f"{x*100:.1f}" for x in r["per_repetition_asr"])
            print(f"{r['id']:<10}{'yes':>5}{r['empirical_asr']*100:9.1f} "
                  f"[{r['empirical_ci'][0]*100:5.1f},{r['empirical_ci'][1]*100:5.1f}]"
                  f"{r['analytical_asr']*100:12.1f}{r['abs_diff_vs_analytical']*100:9.2f}  {pr}")
        else:
            print(f"{r['id']:<10}{'  --':>5}{'(counterfactual)':>26}{r['analytical_asr']*100:12.1f}")
    print(f"\nobserved vs analytical over {len(obs)} compositions: "
          f"mean |diff| = {out['agreement']['mean_abs_diff_pp']:.2f} pp, "
          f"max = {out['agreement']['max_abs_diff_pp']:.2f} pp")

    path = os.path.join(HERE, "empirical_quorum.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
