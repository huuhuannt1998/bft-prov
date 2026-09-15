"""
Scaled five-axis evaluation (P1 #8/#9) over a 12-model matrix (6 families x 2 sizes). Collects RAW votes
per model (legit / baseline / injected on the 120-payload scaled corpus) and checkpoints one JSON per
model so a long run is resumable. Statistics (Wilson CIs, phi bootstrap, Fisher, family-vs-size) are
computed separately by analyze_scaled.py from these raw votes.

Usage: PYTHONPATH=. python -m decorrelation.run_scaled_eval [--reps K] [--models tagA,tagB]
"""
from __future__ import annotations
import json
import os
import sys
import time

from consensus.model_vote import OllamaJudge
from decorrelation.heldout_corpus_scaled import build_corpus, HELD_LEGIT

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "scaled")

# 6 families x 2 models (A larger, B smaller) -- lets us separate per-family lineage from per-model size.
MATRIX = {
    "llama":   [("llama3.1:8b", 8.0), ("llama3.2:3b", 3.0)],
    "qwen":    [("qwen2.5:7b", 7.6), ("qwen2.5:3b", 3.0)],
    "mistral": [("mistral:7b", 7.2), ("mistral-nemo:12b", 12.0)],
    "gemma":   [("gemma3:4b", 4.3), ("gemma2:9b", 9.0)],
    "phi":     [("phi4-mini:latest", 3.8), ("phi3.5:3.8b", 3.8)],
    "granite": [("granite3.1-dense:8b", 8.0), ("granite3.1-moe:3b", 3.0)],
}
PRIMARY = {"llama": "llama3.1:8b", "qwen": "qwen2.5:7b", "mistral": "mistral:7b", "gemma": "gemma3:4b"}


def modal(votes):
    return sum(1 for v in votes if v) >= (len(votes) + 1) // 2


def run_model(tag: str, family: str, params: float, corpus, reps: int) -> dict:
    judge = OllamaJudge(tag, provenance=True)
    legit, baseline, injected = {}, {}, {}
    for c in HELD_LEGIT:
        cid, task, dev, cmd, ing = c
        legit[cid] = modal([judge(dev, cmd, task, ing) for _ in range(reps)])
    for c in corpus:
        baseline[c.cid] = modal([judge(c.device, c.command, c.trusted_task, c.ingested_benign)
                                 for _ in range(reps)])
        injected[c.cid] = modal([judge(c.device, c.command, c.trusted_task, c.ingested_injected)
                                 for _ in range(reps)])
    return {"tag": tag, "family": family, "params": params, "reps": reps,
            "legit": legit, "baseline": baseline, "injected": injected}


def main():
    os.makedirs(OUT, exist_ok=True)
    reps = 1
    only = None
    for i, a in enumerate(sys.argv):
        if a == "--reps":
            reps = int(sys.argv[i + 1])
        if a == "--models":
            only = set(sys.argv[i + 1].split(","))
    corpus = build_corpus()
    jobs = [(tag, fam, p) for fam, lst in MATRIX.items() for (tag, p) in lst]
    if only:
        jobs = [j for j in jobs if j[0] in only]
    print(f"scaled eval: {len(jobs)} models x ({len(corpus)} inj + {len(corpus)} base + {len(HELD_LEGIT)} legit) x reps={reps}")
    for tag, fam, p in jobs:
        safe = tag.replace(":", "_").replace("/", "_")
        path = os.path.join(OUT, f"{safe}.json")
        if os.path.exists(path):
            print(f"  skip {tag} (done)"); continue
        t0 = time.time()
        res = run_model(tag, fam, p, corpus, reps)
        json.dump(res, open(path, "w"), indent=1)
        asr = sum(res["injected"].values()) / len(corpus)
        print(f"  {tag:22s} fam={fam:8s} ASR={asr*100:4.0f}%  ({time.time()-t0:.0f}s)")
    print("done. run: python -m decorrelation.analyze_scaled")


if __name__ == "__main__":
    main()
