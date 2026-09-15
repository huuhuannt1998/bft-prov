"""Sweep the expanded benign controls over the deployable pool (reviewer 4.3).

One repetition per (agent, control): the measured control-channel repetition unanimity in the main sweep
is 100.0%, so additional repetitions on this channel carry no information. Correct decision on every
control is DENY; an approval is a false approval.
"""
from __future__ import annotations
import json, os, time
from decorrelation.controls_expanded import CONTROLS
from decorrelation.defenses import DefenseJudge, KnownAnswerJudge, OllamaError
from decorrelation.model_matrix import MATRIX

OUT = os.path.join(os.path.dirname(__file__), "controls_expanded.json")
DEPLOYABLE = ["provenance", "struq", "hierarchy", "spotlight", "known_answer"]

def main():
    done = json.load(open(OUT))["cells"] if os.path.exists(OUT) else {}
    t0 = time.time(); n = 0
    total = len(MATRIX) * len(DEPLOYABLE)
    for m in MATRIX:
        for d in DEPLOYABLE:
            key = f"{m.tag}|{d}"; n += 1
            if key in done: continue
            j = KnownAnswerJudge(m.tag) if d == "known_answer" else DefenseJudge(m.tag, d)
            try:
                raw = {c.cid: bool(j(c.device, c.command, c.trusted_task, c.ingested_benign))
                       for c in CONTROLS}
            except OllamaError as e:
                print(f"  ERROR {key}: {e}"); continue
            done[key] = {"tag": m.tag, "defense": d, "family": m.family, "raw": raw}
            fp = sum(raw.values()) / len(raw)
            print(f"[{n}/{total}] {key:<40} control FP={fp*100:5.1f}%  ({(time.time()-t0)/60:.1f} min)",
                  flush=True)
            tmp = OUT + ".tmp"
            json.dump({"cells": done, "controls": [c.cid for c in CONTROLS], "reps": 1}, open(tmp, "w"))
            os.replace(tmp, OUT)
    print(f"complete: {len(done)} cells in {(time.time()-t0)/60:.1f} min")

if __name__ == "__main__":
    main()
