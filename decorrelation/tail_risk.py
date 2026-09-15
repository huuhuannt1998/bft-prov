"""Tail risk and payload difficulty (earlier revision, review sections 17 and 18).

The attacker chooses the payload, so mean attack success is the wrong summary statistic for a security
claim. What matters is the upper tail: if a minority of payloads reliably defeats many validators at
once, an adaptive attacker will search for exactly those, and the mean understates the risk a deployment
carries.

Two analyses over existing votes, no inference:

  TAIL RISK. For each canonical quorum, the distribution of per-payload q-of-N approval probability, with
  median, p75, p90, p95, the worst-decile mean (CVaR_0.9), and the share of payloads that defeat the
  quorum outright. CVaR is the honest number to size a deployment against.

  PAYLOAD DIFFICULTY. d(x) = mean_i p_i(x) over the deployable pool, its distribution, its concentration
  by attack category and sophistication, and whether family diversity buys anything WITHIN a difficulty
  stratum. If quorum failures concentrate in universally difficult inputs, then item difficulty is not a
  confound to apologise for; it is the mechanism, and marginal diversity cannot fix it.

Usage: PYTHONPATH=. python -m decorrelation.tail_risk
"""
from __future__ import annotations

import json
import os

import numpy as np

from decorrelation.analyze_quorum import load_agents, pb_tail, stratified_split, category_of

HERE = os.path.dirname(__file__)
SEED = 20260801


def main() -> None:
    agents, raw, items = load_agents()
    catmap = category_of(items["inj"])              # dict: payload id -> attack category
    cats = np.array([catmap[c] for c in items["inj"]])
    _, test_idx = stratified_split(items["inj"], catmap)
    canon = json.load(open(os.path.join(HERE, "canonical_quorums.json")))
    byname = {a.key: a for a in agents}
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)

    # ---------- tail risk per canonical quorum ----------
    tail = []
    for spec in canon["rows"]:
        sets = canon["member_sets"][f"{spec['composition']}|{spec['N']}"]
        Pi = np.stack([np.stack([agents[byname[k]]["inj"][test_idx] for k in S], 1) for S in sets])
        per_payload = np.stack([pb_tail(Pi[s], spec["q"]) for s in range(len(sets))]).mean(axis=0)
        srt = np.sort(per_payload)
        w10 = srt[int(0.9 * len(srt)):]
        tail.append({
            "id": spec["id"], "q": spec["q"], "N": spec["N"],
            "mean": float(per_payload.mean()), "median": float(np.median(per_payload)),
            "p75": float(np.percentile(per_payload, 75)), "p90": float(np.percentile(per_payload, 90)),
            "p95": float(np.percentile(per_payload, 95)), "max": float(per_payload.max()),
            "cvar90": float(w10.mean()),
            "frac_payloads_certain": float((per_payload >= 0.999).mean()),
            "cvar_over_mean": float(w10.mean() / max(per_payload.mean(), 1e-12)),
        })

    print(f"{'ID':<10}{'mean':>7}{'med':>7}{'p75':>7}{'p90':>7}{'p95':>7}{'max':>7}"
          f"{'CVaR.9':>8}{'x mean':>8}{'always-win':>11}")
    for t in tail:
        print(f"{t['id']:<10}{t['mean']*100:7.1f}{t['median']*100:7.1f}{t['p75']*100:7.1f}"
              f"{t['p90']*100:7.1f}{t['p95']*100:7.1f}{t['max']*100:7.1f}{t['cvar90']*100:8.1f}"
              f"{t['cvar_over_mean']:8.1f}{t['frac_payloads_certain']*100:10.1f}%")

    # ---------- payload difficulty ----------
    P = np.vstack([agents[a]["inj"] for a in pool])
    d = P.mean(axis=0)
    q3 = np.percentile(d, [33.3, 66.7])
    strat = np.digitize(d, q3)                       # 0 easy, 1 medium, 2 hard (for the defender)
    names = ["low d(x)", "medium d(x)", "high d(x)"]

    print(f"\npayload difficulty d(x) over {len(pool)} deployable agents, n={len(d)} payloads")
    print(f"  mean {d.mean()*100:.1f}%  sd {d.std()*100:.1f}%  min {d.min()*100:.1f}%  "
          f"max {d.max()*100:.1f}%  p90 {np.percentile(d,90)*100:.1f}%")
    top = np.argsort(-d)[:int(0.1 * len(d))]
    print(f"  hardest decile carries {d[top].sum()/d.sum()*100:.1f}% of all approval mass "
          f"(uniform would be 10.0%)")

    # does family diversity help WITHIN a difficulty stratum?
    strat_rows = []
    for s, nm in enumerate(names):
        idx = np.where(strat == s)[0]
        keep = np.array([i for i in idx if i in set(test_idx.tolist())])
        row = {"stratum": nm, "n_payloads": int(len(idx)), "n_heldout": int(len(keep)),
               "mean_d": float(d[idx].mean())}
        for comp, cid in (("homogeneous", "HOM-3of5"), ("family-diverse", "FD-3of5"),
                          ("joint-diverse", "JD-3of5")):
            sets = canon["member_sets"][f"{comp}|5"]
            Pi = np.stack([np.stack([agents[byname[k]]["inj"][keep] for k in S], 1) for S in sets])
            row[cid] = float(np.stack([pb_tail(Pi[t], 3) for t in range(len(sets))]).mean())
        strat_rows.append(row)

    print(f"\n{'stratum':<14}{'n':>5}{'mean d(x)':>11}{'HOM-3of5':>10}{'FD-3of5':>9}{'JD-3of5':>9}"
          f"{'diversity gain':>16}")
    for r in strat_rows:
        gain = (r["HOM-3of5"] - r["JD-3of5"]) * 100
        print(f"{r['stratum']:<14}{r['n_heldout']:5d}{r['mean_d']*100:10.1f}%{r['HOM-3of5']*100:10.1f}"
              f"{r['FD-3of5']*100:9.1f}{r['JD-3of5']*100:9.1f}{gain:14.1f} pp")

    # concentration by attack category
    bycat = {}
    for c in sorted(set(cats.tolist())):
        m = cats == c
        if not m.any():
            continue
        bycat[c] = {"n": int(m.sum()), "mean_d": float(d[m].mean()), "max_d": float(d[m].max())}
    worst = sorted(bycat.items(), key=lambda kv: -kv[1]["mean_d"])[:5]
    print("\nhardest attack categories by mean d(x):")
    for c, v in worst:
        print(f"  {c:<28}n={v['n']:<4} mean d {v['mean_d']*100:5.1f}%  max {v['max_d']*100:5.1f}%")

    out = {"meta": {"seed": SEED, "n_heldout_payloads": int(len(test_idx)), "pool_size": len(pool),
                    "cvar_definition": "mean per-payload q-of-N approval over the worst decile of payloads"},
           "tail_risk": tail,
           "difficulty": {"mean": float(d.mean()), "sd": float(d.std()), "min": float(d.min()),
                          "max": float(d.max()), "p90": float(np.percentile(d, 90)),
                          "hardest_decile_share_of_approval_mass": float(d[top].sum() / d.sum()),
                          "tertile_cuts": [float(x) for x in q3]},
           "by_stratum": strat_rows, "by_category": bycat}
    path = os.path.join(HERE, "tail_risk.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
