"""P0-A: aligned versus payload-permuted joint approval (earlier revision).

The reviewer objection this closes: joint failure above the product of pooled marginals is a predictable
consequence of heterogeneous payload difficulty, not a surprising failure mode. That objection is right
about the mechanism and wrong about the significance, and a permutation test separates the two.

For an unordered pair (i, j) we compare

    J_aligned = E_x[ p_i(x) p_j(x) ]          both validators read the SAME payload
    J_perm    = E_x[ p_i(x) p_j(pi(x)) ]      j's payloads are permuted; alignment destroyed

The permutation preserves each agent's marginal rate and the full shape of its per-payload failure
distribution, and destroys only the alignment on one attacker-chosen input. Whatever separates aligned
from permuted is therefore attributable to shared input rather than to either agent's difficulty profile.
This is exactly the quantity a quorum designer is exposed to, because a real attacker sends one payload
to every replica.

Usage: PYTHONPATH=. python -m decorrelation.permutation_test
"""
from __future__ import annotations

import itertools
import json
import os

import numpy as np

from decorrelation.analyze_quorum import load_agents, pair_class, PAIR_CLASSES

HERE = os.path.dirname(__file__)
SEED = 20260801
N_PERM = 2000


def main() -> None:
    agents, raw, items = load_agents()
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)
    P = np.vstack([agents[a]["inj"] for a in pool])          # [agents, payloads] per-payload rates
    nA, nX = P.shape
    rng = np.random.default_rng(SEED)

    # one permutation bank, reused across every pair so pairs are compared under identical shuffles
    perms = np.stack([rng.permutation(nX) for _ in range(N_PERM)])

    pairs = [(i, j) for i, j in itertools.combinations(range(nA), 2)]
    pairs += [(i, i) for i in range(nA)]                      # replica pairs: one config drawn twice
    rows = []
    for i, j in pairs:
        cls = PAIR_CLASSES[0] if i == j else pair_class(pool[i], pool[j])
        pi, pj = P[i], P[j]
        aligned = float(np.mean(pi * pj))
        perm = (pi[None, :] * pj[perms]).mean(axis=1)         # [N_PERM]
        rows.append({
            "i": pool[i].key, "j": pool[j].key, "category": cls,
            "marg_i": float(pi.mean()), "marg_j": float(pj.mean()),
            "aligned": aligned,
            "perm_mean": float(perm.mean()),
            "perm_lo": float(np.percentile(perm, 2.5)),
            "perm_hi": float(np.percentile(perm, 97.5)),
            "ratio": aligned / max(perm.mean(), 1e-12),
            "excess_abs": aligned - float(perm.mean()),
            # one-sided permutation p-value: how often does destroying alignment reach the aligned value?
            "p_perm": float((perm >= aligned).mean()),
        })

    out = {"meta": {"seed": SEED, "n_perm": N_PERM, "n_payloads": nX, "pool_size": nA,
                    "n_pairs": len(pairs),
                    "note": "permutation preserves each agent's marginal and per-payload failure "
                            "distribution; it destroys only alignment on the same payload"},
           "pairs": rows, "by_category": {}}

    print(f"{'pair category':<30}{'aligned':>9}{'permuted [95% CI]':>24}{'ratio':>8}{'excess':>10}{'p':>8}")
    for c in PAIR_CLASSES:
        sel = [r for r in rows if r["category"] == c]
        if not sel:
            continue
        A = np.array([r["aligned"] for r in sel])
        M = np.array([r["perm_mean"] for r in sel])
        lo = np.array([r["perm_lo"] for r in sel]).mean()
        hi = np.array([r["perm_hi"] for r in sel]).mean()
        # pair-level bootstrap over the pairs in this category
        bs = rng.integers(0, len(sel), (2000, len(sel)))
        rb = A[bs].mean(axis=1) / np.maximum(M[bs].mean(axis=1), 1e-12)
        summ = {"n_pairs": len(sel), "aligned": float(A.mean()), "permuted": float(M.mean()),
                "perm_lo": float(lo), "perm_hi": float(hi),
                "ratio": float(A.mean() / max(M.mean(), 1e-12)),
                "ratio_ci": [float(np.percentile(rb, 2.5)), float(np.percentile(rb, 97.5))],
                "excess_abs": float(A.mean() - M.mean()),
                "median_p_perm": float(np.median([r["p_perm"] for r in sel]))}
        out["by_category"][c] = summ
        print(f"{c:<30}{summ['aligned']:9.4f}{summ['permuted']:12.4f} [{lo:.4f},{hi:.4f}]"
              f"{summ['ratio']:8.2f}{summ['excess_abs']:10.4f}{summ['median_p_perm']:8.4f}")

    path = os.path.join(HERE, "permutation_test.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
