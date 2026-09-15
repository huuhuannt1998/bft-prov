"""
Analysis for the scaled sweep (P1 #6/#7/#9). Loads decorrelation/scaled/*.json (raw per-model votes) and
produces, with proper statistics and no bare point estimates:
  - per-model five-axis(a-c) table: utility, benign-unsafe (baseline), single-shot IPI ASR + marginal, all
    with Wilson 95% CIs;
  - family-vs-size: the two models per family side by side (tests lineage vs capability);
  - the deployed 4-family quorum: per-family ASR+CI, quorum-defeat rate+CI, phi(mistral,gemma) with a
    payload-bootstrap CI under the pre-registered rule, Fisher robust-vs-weak;
  - per-category ASR (which framings transfer), incl. the new rag-poison category.
Writes scaled_analysis.json. Adaptive/multi-turn axes (d,e) are merged in from their own result files if present.
"""
from __future__ import annotations
import glob
import json
import os
import statistics as st

from decorrelation.heldout_corpus_scaled import build_corpus, CATEGORIES, WEAK, ROBUST
from decorrelation.run_scaled_eval import MATRIX, PRIMARY
from decorrelation.stats import wilson, fisher_exact, bootstrap_phi, interpret_phi, fmt_ci

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "scaled")


def load():
    models = {}
    for p in sorted(glob.glob(os.path.join(OUT, "*.json"))):
        d = json.load(open(p))
        models[d["tag"]] = d
    return models


def main():
    corpus = build_corpus()
    cids = [c.cid for c in corpus]
    cat_of = {c.cid: c.category for c in corpus}
    models = load()
    if not models:
        print("no scaled/*.json yet"); return
    n = len(cids)
    print(f"loaded {len(models)} models; {n} injected payloads\n")

    # ---- per-model five-axis (a-c) with Wilson CIs ----
    print("=== per-model: utility | benign-unsafe(base) | single-shot ASR | marginal  (95% Wilson CI) ===")
    per_model = {}
    for tag, d in models.items():
        legit = d["legit"]; base = d["baseline"]; inj = d["injected"]
        util_k = sum(1 for v in legit.values() if v); util_n = len(legit)
        base_k = sum(1 for c in cids if base.get(c)); asr_k = sum(1 for c in cids if inj.get(c))
        util = wilson(util_k, util_n); b = wilson(base_k, n); a = wilson(asr_k, n)
        marg = a[0] - b[0]
        per_model[tag] = {"family": d["family"], "params": d["params"],
                          "utility": util, "baseline": b, "asr": a, "marginal": marg,
                          "asr_k": asr_k, "base_k": base_k}
        print(f"  {tag:22s} util {util[0]*100:3.0f}%  base {fmt_ci(base_k,n):>16s}  "
              f"ASR {fmt_ci(asr_k,n):>16s}  marg {marg*100:+3.0f}")

    # ---- family vs size ----
    print("\n=== family vs size (ASR of larger vs smaller model per family) ===")
    for fam, lst in MATRIX.items():
        row = []
        for tag, p in lst:
            if tag in per_model:
                row.append(f"{tag.split(':')[0]}({p}B) {per_model[tag]['asr'][0]*100:.0f}%")
        print(f"  {fam:8s}: " + "  vs  ".join(row))

    # ---- deployed 4-family quorum (primary model per family) ----
    print("\n=== deployed 4-family quorum (primary models), n=%d ===" % n)
    fam_inj = {f: models[PRIMARY[f]]["injected"] for f in PRIMARY if PRIMARY[f] in models}
    if len(fam_inj) == 4:
        for f in ["llama", "qwen", "mistral", "gemma"]:
            k = sum(1 for c in cids if fam_inj[f].get(c))
            print(f"  {f:8s} ASR {fmt_ci(k,n)}")
        defeats = sum(1 for c in cids if sum(1 for f in fam_inj if fam_inj[f].get(c)) >= 3)
        print(f"  QUORUM DEFEAT (>=3/4): {fmt_ci(defeats, n)}")
        # phi(mistral,gemma) with bootstrap CI + rule
        pairs = [(1 if fam_inj["mistral"].get(c) else 0, 1 if fam_inj["gemma"].get(c) else 0) for c in cids]
        bs = bootstrap_phi(pairs)
        print(f"  phi(mistral,gemma) point={bs['point'] if bs['point'] is None else round(bs['point'],3)} "
              f"CI[{None if bs['lo'] is None else round(bs['lo'],3)},{None if bs['hi'] is None else round(bs['hi'],3)}] "
              f"undef={bs['undefined_frac']:.2f}")
        print(f"    -> {interpret_phi(bs)}")
        # Fisher robust-vs-weak: approvals pooled
        weak_k = sum(1 for f in WEAK for c in cids if fam_inj[f].get(c)); weak_tot = 2 * n
        rob_k = sum(1 for f in ROBUST for c in cids if fam_inj[f].get(c)); rob_tot = 2 * n
        pf = fisher_exact(weak_k, weak_tot - weak_k, rob_k, rob_tot - rob_k)
        print(f"  robust-vs-weak Fisher: weak {weak_k}/{weak_tot} vs robust {rob_k}/{rob_tot}, p={pf:.2e}")

    # ---- per-category ASR (pooled over primary 4 families) ----
    print("\n=== per-category injected approval (pooled, primary 4 families) ===")
    if len(fam_inj) == 4:
        for cat in CATEGORIES:
            ccids = [c for c in cids if cat_of[c] == cat]
            k = sum(1 for f in fam_inj for c in ccids if fam_inj[f].get(c)); tot = 4 * len(ccids)
            print(f"  {cat:22s} {fmt_ci(k, tot)}")

    out = {"n": n, "per_model": {t: {k: (v if not isinstance(v, tuple) else list(v)) for k, v in d.items()}
                                 for t, d in per_model.items()}}
    json.dump(out, open(os.path.join(HERE, "scaled_analysis.json"), "w"), indent=1)
    print("\nwrote scaled_analysis.json")


if __name__ == "__main__":
    main()
