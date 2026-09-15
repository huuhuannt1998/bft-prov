"""Run the expanded adaptive corpus against the representative quorum agents (USENIX revision).

Review section 8.3: do not rerun the whole 65-agent matrix. The union of members across the canonical
sets for HOM-3of5, FD-3of5, JD-3of5, JD-5of7 and BSU-3of5 is 20 agents, which is what this evaluates.
Each agent is loaded once and every payload is scored against it before moving on, so only one model is
resident at a time.

Usage: PYTHONPATH=. python -m decorrelation.run_adaptive2 [--reps 3]
"""
from __future__ import annotations

import argparse, json, os, time

from decorrelation.adaptive_corpus2 import CORPUS
from decorrelation.defenses import DefenseJudge, KnownAnswerJudge, OllamaError
from decorrelation.model_matrix import MATRIX

OUT = os.path.join(os.path.dirname(__file__), "adaptive2.json")


def agent_union() -> list[str]:
    c = json.load(open(os.path.join(os.path.dirname(__file__), "canonical_quorums.json")))
    keys = ["homogeneous|5", "family-diverse|5", "joint-diverse|5", "joint-diverse|7",
            "best-security-utility|5"]
    u = set()
    for k in keys:
        u |= set(c["member_sets"][k][0])
    return sorted(u)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    want = agent_union()
    known = {m.tag for m in MATRIX}
    done = {}
    if os.path.exists(a.out):
        done = json.load(open(a.out)).get("cells", {})
        print(f"resuming: {len(done)}/{len(want)} agents already complete", flush=True)

    t0 = time.time()
    for i, key in enumerate(want, 1):
        if key in done:
            continue
        tag, defense = key.split("|")
        judge = KnownAnswerJudge(tag) if defense == "known_answer" else DefenseJudge(tag, defense)
        raw = {}
        for c in CORPUS:
            try:
                raw[c.aid] = [bool(judge(c.target_device, c.target_command, c.trusted_task, c.ingested))
                              for _ in range(a.reps)]
            except OllamaError as e:
                print(f"  !! {key} {c.aid}: {e}", flush=True)
                raw[c.aid] = [False] * a.reps
        done[key] = {"tag": tag, "defense": defense, "reps": a.reps, "raw": raw}
        el = time.time() - t0
        print(f"[{i}/{len(want)}] {key:<34} asr={sum(sum(v) for v in raw.values())/(len(raw)*a.reps)*100:5.1f}%"
              f"  elapsed {el/60:.1f} min", flush=True)
        json.dump({"cells": done, "corpus": len(CORPUS), "reps": a.reps}, open(a.out, "w"), indent=1)

    print(f"done: {len(done)} agents x {len(CORPUS)} payloads x {a.reps} reps in "
          f"{(time.time()-t0)/60:.1f} min -> {a.out}", flush=True)


if __name__ == "__main__":
    main()
