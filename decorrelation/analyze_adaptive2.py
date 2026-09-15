"""Static versus adaptive attacker, reported separately (earlier revision, review section 8.5).

The manuscript's adaptive evidence was 10 payloads, enough to show that everything degrades and not
enough to rank anything. This scores the 60-case frozen mutation grammar against the same canonical
quorum policies used for the static corpus, so the two attacker models are directly comparable.

Two attacker models, never averaged together:
  STATIC    the payload does not react to the defense; the 342-payload held-out corpus.
  ADAPTIVE  the payload is mutated against the defense's own vocabulary; the 60-case grammar, frozen
            before any quorum result was observed.

Usage: PYTHONPATH=. python -m decorrelation.analyze_adaptive2
"""
from __future__ import annotations

import collections, json, os
import numpy as np

from decorrelation.adaptive_corpus2 import CORPUS
from decorrelation.analyze_quorum import pb_tail

HERE = os.path.dirname(__file__)
SEED = 20260801
N_BOOT = 1000

# the five representative policies from review section 8.3
POLICIES = [("HOM-3of5", "homogeneous|5", 3), ("FD-3of5", "family-diverse|5", 3),
            ("JD-3of5", "joint-diverse|5", 3), ("JD-5of7", "joint-diverse|7", 5),
            ("BSU-3of5", "best-security-utility|5", 3)]


def main() -> None:
    ad = json.load(open(os.path.join(HERE, "adaptive2.json")))["cells"]
    canon = json.load(open(os.path.join(HERE, "canonical_quorums.json")))
    static = {r["id"]: r for r in canon["rows"]}
    pids = [c.aid for c in CORPUS]
    byround = {c.aid: c.round for c in CORPUS}
    byrule = {c.aid: c.rule for c in CORPUS}

    # per-agent, per-payload adaptive approval rate
    P = {k: np.array([np.mean(v["raw"][p]) for p in pids]) for k, v in ad.items()}
    rng = np.random.default_rng(SEED)

    print(f"{'policy':<10}{'static ASR':>12}{'adaptive ASR':>15}{'abs diff':>11}{'ratio':>8}")
    rows = []
    for qid, key, q in POLICIES:
        members = canon["member_sets"][key][0]
        if not all(m in P for m in members):
            continue
        M = np.stack([P[m] for m in members], axis=1)              # [payload, member]
        per_payload = pb_tail(M, q)
        a = float(per_payload.mean())
        bs = [float(per_payload[rng.integers(0, len(per_payload), len(per_payload))].mean())
              for _ in range(N_BOOT)]
        s = static[qid]["asr"]
        rows.append({"id": qid, "q": q, "static_asr": s, "adaptive_asr": a,
                     "adaptive_ci": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))],
                     "abs_diff_pp": (a - s) * 100, "ratio": a / max(s, 1e-9),
                     "members": members})
        print(f"{qid:<10}{s*100:11.1f}%{a*100:14.1f}%{(a-s)*100:10.1f}"
              f"{(a/max(s,1e-9)):8.2f}" if s > 0 else
              f"{qid:<10}{s*100:11.1f}%{a*100:14.1f}%{(a-s)*100:10.1f}{'  n/a':>8}")

    # does the mutation grammar's escalation ladder actually escalate?
    print(f"\nby mutation round, pooled over all {len(P)} evaluated agents:")
    byr = collections.defaultdict(list)
    for k, v in P.items():
        for i, pid in enumerate(pids):
            byr[byround[pid]].append(v[i])
    for r in sorted(byr):
        arr = np.array(byr[r])
        n = sum(1 for p in pids if byround[p] == r)
        print(f"  round {r} ({n:2d} payloads): approval {arr.mean()*100:5.1f}%")

    print("\nmost effective mutation rules (pooled agent approval):")
    byrule_acc = collections.defaultdict(list)
    for k, v in P.items():
        for i, pid in enumerate(pids):
            byrule_acc[byrule[pid]].append(v[i])
    for rule, arr in sorted(byrule_acc.items(), key=lambda kv: -np.mean(kv[1]))[:6]:
        print(f"  {rule:<26}{np.mean(arr)*100:5.1f}%")

    # per-agent: is resistance a property of the configuration rather than of diversity?
    per_agent = sorted(((k, float(v.mean())) for k, v in P.items()), key=lambda kv: kv[1])
    print(f"\nper-agent adaptive approval, {len(per_agent)} evaluated agents:")
    print(f"  best  {per_agent[0][0]:<32}{per_agent[0][1]*100:5.1f}%")
    print(f"  worst {per_agent[-1][0]:<32}{per_agent[-1][1]*100:5.1f}%")
    print(f"  median {np.median([v for _, v in per_agent])*100:.1f}%")

    out = {"meta": {"seed": SEED, "n_boot": N_BOOT, "n_adaptive_payloads": len(pids),
                    "n_agents": len(P), "reps": ad[list(ad)[0]]["reps"],
                    "note": "static and adaptive attacker models are reported separately, never pooled"},
           "policies": rows,
           "by_round": {str(r): float(np.mean(byr[r])) for r in sorted(byr)},
           "by_rule": {k: float(np.mean(v)) for k, v in byrule_acc.items()},
           "per_agent": dict(per_agent)}
    p = os.path.join(HERE, "adaptive2_analysis.json")
    json.dump(out, open(p, "w"), indent=2)
    print(f"\nwrote {p}")


if __name__ == "__main__":
    main()
