"""Adaptive-attacker sweep over the FULL deployable agent pool (IoT-J revision, reviewer C2).

The non-adaptive corpus admits a training-selected agent that reaches 0% attack success at full
utility, which would suggest agent selection solves the problem. That inference is only sound if the
attacker does not adapt. The earlier adaptive capstone used a four-family pool on five targets, a
different experimental frame from the 65-agent pool the quorum evaluation uses, so it cannot answer the
objection inside this paper.

This script closes that gap: it runs the SAME forged-authorization payloads (decorrelation/adaptive.py,
two rounds per target) against every (model configuration, defense) agent in the deployable pool, three
repetitions each, so the adaptive condition can be scored with exactly the quorum machinery used for the
non-adaptive corpus.

Output: decorrelation/adaptive_pool.json, keyed the same way as the rq1 cells so analyze_quorum can read
either corpus.

Usage: PYTHONPATH=. python -m decorrelation.run_adaptive_pool [--reps 3]
"""
from __future__ import annotations

import argparse
import json
import os
import time

from decorrelation.adaptive import TARGETS
from decorrelation.defenses import DefenseJudge, KnownAnswerJudge, OllamaError
from decorrelation.model_matrix import MATRIX

OUT = os.path.join(os.path.dirname(__file__), "adaptive_pool.json")
DEPLOYABLE = ["provenance", "struq", "hierarchy", "spotlight", "known_answer"]


def cases():
    """Ten adaptive payloads: five targets x two escalation rounds."""
    out = []
    for t in TARGETS:
        out.append((f"{t.tid}-r1", t.trusted_task, t.device, t.command, t.round1))
        out.append((f"{t.tid}-r2", t.trusted_task, t.device, t.command, t.round2))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    payloads = cases()
    done = {}
    if os.path.exists(a.out):
        done = json.load(open(a.out)).get("cells", {})
        print(f"resuming: {len(done)} cells already complete")

    total = len(MATRIX) * len(DEPLOYABLE)
    t0 = time.time()
    n = 0
    for m in MATRIX:
        for d in DEPLOYABLE:
            key = f"{m.tag}|{d}"
            n += 1
            if key in done:
                continue
            judge = KnownAnswerJudge(m.tag) if d == "known_answer" else DefenseJudge(m.tag, d)
            try:
                raw = {}
                for cid, task, dev, cmd, ing in payloads:
                    raw[cid] = [judge(dev, cmd, task, ing) for _ in range(a.reps)]
            except OllamaError as e:
                print(f"  ERROR {key}: {e} -- skipping, rerun to retry")
                continue
            done[key] = {"tag": m.tag, "defense": d, "family": m.family, "raw": raw}
            asr = sum(sum(v) for v in raw.values()) / (len(raw) * a.reps)
            el = time.time() - t0
            print(f"[{n}/{total}] {key:<40} adaptive ASR={asr*100:5.1f}%  ({el/60:.1f} min)", flush=True)
            tmp = a.out + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"cells": done, "payloads": [c[0] for c in payloads], "reps": a.reps}, f)
            os.replace(tmp, a.out)

    print(f"\ncomplete: {len(done)} cells in {(time.time()-t0)/60:.1f} min -> {a.out}")


if __name__ == "__main__":
    main()
