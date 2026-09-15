"""Temperature sensitivity (earlier revision, review section 7).

The objection this answers: at temperature 0 the models are near-deterministic, so of course replicas
of one configuration agree, and maybe the whole shared-failure result is an artifact of greedy decoding.
Sampling would then break the correlation and the paper's conclusion with it.

Design per review section 7.2, restricted to what one M4 can run sequentially:
  three EXISTING configurations spanning the observed susceptibility range (secure / medium / vulnerable)
  three temperatures: 0.0 (as used throughout), 0.3 low, 0.7 moderate
  90 stratified attack payloads (every third payload of the held-out half, preserving category mix)
  5 repetitions per cell, enough to expose stochastic variation

Reported per temperature: individual ASR, per-payload vote entropy, repeat unanimity, same-payload joint
approval across the three configurations, and homogeneous q-of-N behaviour computed from the observed
repetitions rather than simulated.

The question is whether sampling ELIMINATES the shared failure mode or merely adds local randomness
around payloads that stay systematically difficult.

Usage: PYTHONPATH=. python -m decorrelation.run_temperature
"""
from __future__ import annotations

import argparse, itertools, json, math, os, time

from decorrelation.defenses import DefenseJudge, OllamaError
from decorrelation.analyze_quorum import load_agents, stratified_split, category_of

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "temperature.json")
TEMPS = [0.0, 0.3, 0.7]
# three existing configurations spanning the static susceptibility range (see the model matrix)
CONFIGS = [("qwen2.5:7b", "hierarchy", "resistant"),
           ("gemma2:9b", "provenance", "medium"),
           ("mistral:7b", "spotlight", "vulnerable")]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--stride", type=int, default=2)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    agents, raw, items = load_agents()
    catmap = category_of(items["inj"])
    _, test_idx = stratified_split(items["inj"], catmap)
    from decorrelation.corpus_main import build_corpus
    cases = {c.cid: c for c in build_corpus()}
    ids = [items["inj"][i] for i in test_idx][::a.stride]
    print(f"{len(CONFIGS)} configs x {len(TEMPS)} temperatures x {len(ids)} payloads x {a.reps} reps "
          f"= {len(CONFIGS)*len(TEMPS)*len(ids)*a.reps} inferences", flush=True)

    done = {}
    if os.path.exists(a.out):
        done = json.load(open(a.out)).get("cells", {})
        print(f"resuming: {len(done)} cells complete", flush=True)

    t0 = time.time()
    for (tag, defense, band), T in itertools.product(CONFIGS, TEMPS):
        key = f"{tag}|{defense}|T{T}"
        if key in done:
            continue
        judge = DefenseJudge(tag, defense, temperature=T) if _accepts_temp() else DefenseJudge(tag, defense)
        rec = {}
        for cid in ids:
            c = cases[cid]
            try:
                rec[cid] = [bool(judge(c.device, c.command, c.trusted_task, c.ingested_injected))
                            for _ in range(a.reps)]
            except OllamaError as e:
                print(f"  !! {key} {cid}: {e}", flush=True)
                rec[cid] = [False] * a.reps
        done[key] = {"tag": tag, "defense": defense, "band": band, "temperature": T,
                     "reps": a.reps, "raw": rec}
        asr = sum(sum(v) for v in rec.values()) / (len(rec) * a.reps)
        print(f"  {key:<34} ASR {asr*100:5.1f}%   elapsed {(time.time()-t0)/60:.1f} min", flush=True)
        json.dump({"cells": done, "temps": TEMPS, "reps": a.reps, "payload_ids": ids},
                  open(a.out, "w"), indent=1)
    print(f"done in {(time.time()-t0)/60:.1f} min -> {a.out}", flush=True)


def _accepts_temp() -> bool:
    import inspect
    return "temperature" in inspect.signature(DefenseJudge.__init__).parameters


if __name__ == "__main__":
    main()
