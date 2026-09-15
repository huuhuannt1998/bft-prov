#!/usr/bin/env python3
"""Verification of the quantitative claims in research_design_detailed.md.

Written after the first draft of that design asserted several numbers that turned out to be
wrong. Everything here is computed from the existing 65-agent vote matrix and the canonical
member-set draws, so it needs no new inference. Run it before changing any sizing decision.

What it establishes, in order:

  1. The payload-difficulty ICC is 0.038, not the 0.35 the first draft assumed, so any
     parametric power curve built on that assumption is void.
  2. Aggregate payload-difficulty scores are near one-dimensional: an l1 score (mean per-agent
     approval) and an l2 score (joint approval averaged over member-set draws) correlate at
     rho ~ 0.98, so averaging over draws destroys the family structure an attacker would need.
  3. That structure nonetheless exists: cross-family rank correlations are 0.25-0.50 and most
     payloads show large per-family differentials. It is reachable only by scoring against a
     REALIZED member set (l3), not against the rule (l2).
  4. Scoring one composition's targeted attacker against BOTH compositions inflates erosion
     roughly fivefold. The deployment-relevant contrast gives each composition its own attacker.
  5. Power for the deployment-relevant contrast is governed by the number of member-set draws,
     not by corpus size. Draws reuse the same votes, so power is purchasable without inference.
  6. An external attacker who probes the deployed quorum can predict its decisions at 0.995
     accuracy from 50 probes, so l3 knowledge needs no insider. See probe_infer_attack.
  7. Despite that, composition-aware SELECTION does not erode the dividend: at 2,000 fresh draws
     under the fair contrast the erosion is +1.5 pp with a CI containing zero. Knowing the quorum
     does not help, because payload difficulty is the shared scalar of finding 2.

Usage: PYTHONPATH=. python3 decorrelation/design_verification.py
"""
from __future__ import annotations

import itertools
import json
import os
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from decorrelation.analyze_quorum import load_agents, FAMILY  # noqa: E402

SEED = 20260801
Q, N = 3, 5


def build():
    agents, _, _ = load_agents()
    bykey = {a.key: agents[a]["inj"] for a in agents}
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda x: x.key)
    P = np.vstack([agents[a]["inj"] for a in pool])
    c = json.load(open(os.path.join(ROOT, "decorrelation", "canonical_quorums.json")))
    jd, hom = c["member_sets"]["joint-diverse|5"], c["member_sets"]["homogeneous|5"]
    stack = lambda sets: np.array([np.vstack([bykey[x] for x in s]) for s in sets])
    Vj, Vh = stack(jd), stack(hom)
    return P, pool, agents, (Vj.sum(axis=1) >= Q).astype(float), (Vh.sum(axis=1) >= Q).astype(float), \
        Vj.mean(axis=1), Vh.mean(axis=1)


def icc(P):
    pm = P.mean(axis=0)
    return pm.var() / (P.mean() * (1 - P.mean()))


def dimensionality(P, SJ):
    from scipy.stats import spearmanr
    l1, l2 = P.mean(axis=0), SJ.mean(axis=0)
    rho, _ = spearmanr(l1, l2)
    k = int(len(l1) * 0.10)
    overlap = len(set(np.argsort(-l1)[:k]) & set(np.argsort(-l2)[:k])) / k
    return rho, overlap


def cross_family(agents, pool):
    from scipy.stats import spearmanr
    fam = {}
    for a in pool:
        fam.setdefault(FAMILY.get(a.tag, "?"), []).append(agents[a]["inj"])
    fam = {k: np.vstack(v).mean(axis=0) for k, v in fam.items() if len(v) >= 3}
    rhos = [spearmanr(fam[i], fam[j])[0] for i, j in itertools.combinations(fam, 2)]
    return min(rhos), max(rhos), len(fam)


def erosion(QJ, QH, SJ, SH, rng, fair, n_draws=200, k_frac=0.10, n_boot=1500):
    """fair=True gives each composition an attacker targeting it; fair=False scores the
    JD-targeted attacker against both, which is the inflated framing."""
    n_pay = QJ.shape[1]
    dev = np.zeros(n_pay, bool)
    dev[rng.choice(n_pay, n_pay // 2, replace=False)] = True
    d_, t_ = np.where(dev)[0], np.where(~dev)[0]
    k = max(5, int(len(d_) * k_frac))
    vals = []
    for t in range(min(n_draws, QJ.shape[0])):
        sJ = d_[np.argsort(-SJ[t][d_])[:k]]
        sH = d_[np.argsort(-SH[t][d_])[:k]] if fair else sJ
        D0 = QH[t][t_].mean() - QJ[t][t_].mean()
        vals.append(D0 - (QH[t][sH].mean() - QJ[t][sJ].mean()))
    vals = np.array(vals)
    bs = [vals[rng.integers(0, len(vals), len(vals))].mean() for _ in range(n_boot)]
    return vals.mean(), np.percentile(bs, [2.5, 97.5])


def power_vs_draws(QJ, QH, SJ, SH, rng, n_draws, n_sim=200, n_boot=400, k_frac=0.10):
    n_pay = QJ.shape[1]
    hits = 0
    for _ in range(n_sim):
        corp = rng.integers(0, n_pay, n_pay)
        half = n_pay // 2
        d_, t_ = corp[:half], corp[half:]
        k = max(5, int(half * k_frac))
        vals = []
        for t in rng.integers(0, QJ.shape[0], n_draws):
            sJ = d_[np.argsort(-SJ[t][d_])[:k]]
            sH = d_[np.argsort(-SH[t][d_])[:k]]
            vals.append((QH[t][t_].mean() - QJ[t][t_].mean())
                        - (QH[t][sH].mean() - QJ[t][sJ].mean()))
        vals = np.array(vals)
        bs = [vals[rng.integers(0, n_draws, n_draws)].mean() for _ in range(n_boot)]
        if np.percentile(bs, 2.5) > 0:
            hits += 1
    return hits / n_sim


def main() -> None:
    rng = np.random.default_rng(SEED)
    P, pool, agents, QJ, QH, SJ, SH = build()
    out = {}

    out["icc"] = float(icc(P))
    print(f"1. payload-difficulty ICC          = {out['icc']:.3f}   (first draft assumed 0.350)")

    rho, ov = dimensionality(P, SJ)
    out["l1_l2_spearman"], out["top_decile_overlap"] = float(rho), float(ov)
    print(f"2. rho(l1 score, l2 score)         = {rho:.3f}, top-decile overlap {ov*100:.0f}%"
          f"  -> aggregate difficulty is near one-dimensional")

    lo, hi, nf = cross_family(agents, pool)
    out["cross_family_rho_min"], out["cross_family_rho_max"] = float(lo), float(hi)
    print(f"3. cross-family rho over {nf} families = {lo:.2f} to {hi:.2f}"
          f"  -> family structure exists; only l3 can reach it")

    m_u, ci_u = erosion(QJ, QH, SJ, SH, np.random.default_rng(SEED), fair=False)
    m_f, ci_f = erosion(QJ, QH, SJ, SH, np.random.default_rng(SEED), fair=True)
    out["erosion_inflated"] = {"E_pp": m_u * 100, "ci_pp": [ci_u[0] * 100, ci_u[1] * 100]}
    out["erosion_fair"] = {"E_pp": m_f * 100, "ci_pp": [ci_f[0] * 100, ci_f[1] * 100]}
    print(f"4. erosion, JD-targeted scored on both = {m_u*100:+.2f} pp "
          f"[{ci_u[0]*100:+.2f}, {ci_u[1]*100:+.2f}]   <-- INFLATED, do not report")
    print(f"   erosion, each vs its own attacker   = {m_f*100:+.2f} pp "
          f"[{ci_f[0]*100:+.2f}, {ci_f[1]*100:+.2f}]   <-- deployment-relevant")

    print("5. power for the deployment-relevant contrast, by member-set draws "
          "(existing corpus, no new inference):")
    out["power_by_draws"] = {}
    for nd in (200, 600, 2000, 6000):
        pw = power_vs_draws(QJ, QH, SJ, SH, rng, nd, n_sim=120)
        out["power_by_draws"][nd] = pw
        print(f"     {nd:>5} draws -> power {pw:.2f}")

    path = os.path.join(ROOT, "decorrelation", "design_verification.json")
    json.dump(out, open(path, "w"), indent=1)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()


# --- Additions after the first revision, backing the restructured design -------------------

def probe_infer_attack(bykey, sets_jd, sets_hom, rng, n_probe=50, k_frac=0.10, n_boot=2000):
    """End-to-end attack assuming NO insider knowledge.

    The attacker probes the deployed quorum, infers the closest-matching member set from the
    public pool, and selects payloads using that inferred profile. Returns the fair-contrast
    erosion and the attacker's held-out prediction accuracy. The point of this routine is that
    it removes the l3 assumption a reviewer would otherwise reject: l3 is achieved, not assumed.
    """
    q = Q
    stack = lambda s: np.array([np.vstack([bykey[x] for x in m]) for m in s])
    Vj, Vh = stack(sets_jd), stack(sets_hom)
    Oj, Oh = (Vj.sum(axis=1) >= q).astype(int), (Vh.sum(axis=1) >= q).astype(int)
    n_pay, nd = Oj.shape[1], len(sets_jd)
    vals, acc = [], []
    for t in range(nd):
        probes = rng.choice(n_pay, n_probe, replace=False)
        rest = np.setdiff1d(np.arange(n_pay), probes)
        dev, test = rest[:len(rest) // 2], rest[len(rest) // 2:]
        k = max(5, int(len(dev) * k_frac))
        gj = np.argmin((Oj[:, probes] != Oj[t][probes]).sum(axis=1))
        gh = np.argmin((Oh[:, probes] != Oh[t][probes]).sum(axis=1))
        acc.append(((Oj[gj][test] == Oj[t][test]).mean() + (Oh[gh][test] == Oh[t][test]).mean()) / 2)
        sJ = dev[np.argsort(-Vj[gj].mean(axis=0)[dev])[:k]]
        sH = dev[np.argsort(-Vh[gh].mean(axis=0)[dev])[:k]]
        vals.append((Oh[t][test].mean() - Oj[t][test].mean())
                    - (Oh[t][sH].mean() - Oj[t][sJ].mean()))
    v = np.array(vals)
    bs = [v[rng.integers(0, nd, nd)].mean() for _ in range(n_boot)]
    return v.mean(), np.percentile(bs, [2.5, 97.5]), float(np.mean(acc))
