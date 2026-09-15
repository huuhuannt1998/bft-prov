"""Task 6 runner: execute the transferability study over available distinct model families and write
results.md. Uses INSTRUCT/chat models (not coder models), one per family, for a genuine decorrelation
quorum (same-family sizes are NOT decorrelated)."""
from __future__ import annotations
import json
import os
import subprocess

from decorrelation.transfer import run
from decorrelation.injections import CASES

HERE = os.path.dirname(__file__)

# One INSTRUCT model per distinct lineage. Same-family ≠ decorrelated, so we pick across families.
PREFERRED = {
    "llama":   ["llama3.1:8b", "llama3.2:3b"],
    "qwen":    ["qwen2.5:7b", "qwen3:8b"],
    "mistral": ["mistral:7b"],
    "gemma":   ["gemma3:4b", "gemma2:9b"],
}


def available_models() -> set[str]:
    out = subprocess.run(["ollama", "list"], capture_output=True, text=True).stdout
    return {ln.split()[0] for ln in out.splitlines()[1:] if ln.strip()}


def select() -> dict[str, str]:
    have = available_models()
    chosen = {}
    for fam, prefs in PREFERRED.items():
        for tag in prefs:
            if tag in have:
                chosen[fam] = tag
                break
    return chosen


def main():
    models = select()
    print("families selected:", models)
    if len(models) < 2:
        print("need >=2 distinct families; pull more (ollama pull mistral:7b / gemma3:4b)")
        return
    res = run(models)

    fam = res["families"]
    lines = ["# Task 6 — cross-model injection transferability (decorrelation)\n"]
    lines.append("> Honesty (PI directive / trigger d): correlated cross-family flips are a FINDING to "
                 "surface, not a number to massage. Injection payloads are DATA (decorrelation/injections.py).\n")
    lines.append(f"Families (one INSTRUCT model each, distinct lineages): "
                 f"{', '.join(f'{k}={v}' for k,v in models.items())}.")
    lines.append(f"N={res['n']} families, f-bound={res['f_bound']}, quorum (2f+1)={res['quorum']}; "
                 f"{len(CASES)} smart-home indirect injections.\n")

    lines.append("## Per-family attack-success rate (fraction of injections that FLIP the agent)\n")
    lines.append("| Family | model | ASR |")
    lines.append("|--------|-------|----:|")
    for f in fam:
        lines.append(f"| {f} | {models[f]} | {res['asr'][f]*100:.0f}% |")

    lines.append("\n## Flip matrix (1 = flipped by the injection)\n")
    header = "| injection | " + " | ".join(fam) + " | #flipped |"
    lines.append(header)
    lines.append("|" + "---|" * (len(fam) + 2))
    for c in CASES:
        row = [c.cid] + ["1" if res["matrix"][f][c.cid] else "0" for f in fam]
        k = sum(1 for f in fam if res["matrix"][f][c.cid])
        lines.append("| " + " | ".join(row) + f" | {k} |")

    lines.append("\n## Cross-family agreement / co-flip (correlation signal)\n")
    lines.append("| family pair | agreement | both-flipped |")
    lines.append("|-------------|----------:|-------------:|")
    for k, v in res["pair_agree"].items():
        lines.append(f"| {k} | {v['agreement']*100:.0f}% | {v['both_flipped']*100:.0f}% |")

    qd = res["quorum_defeating"]
    lines.append(f"\n## Quorum-defeating events (injections flipping >= {res['quorum']} families at once)\n")
    if qd:
        lines.append(f"**{len(qd)}/{len(CASES)} injections flip a 2f+1 quorum simultaneously** — these "
                     "are correlated faults the BFT quorum CANNOT absorb. Listed: "
                     + ", ".join(f"{cid}({k})" for cid, k in qd) + ".")
        lines.append("\n**Finding (surfaced, not massaged):** for these injections the decorrelation "
                     "premise fails — effective f is reduced. Mitigations to pursue: more diverse "
                     "families/prompts/retrieval, correlation-aware quorum sizing (raise N or require "
                     "cross-family diversity in the quorum), and input sanitization before voting.")
    else:
        lines.append("**0 injections flip a 2f+1 quorum simultaneously** — across these families/cases the "
                     "faults are sufficiently decorrelated for the quorum to absorb them. (Caveat: small "
                     "sample; more families and optimized/transfer attacks would stress this further.)")

    out = os.path.join(HERE, "results.md")
    open(out, "w").write("\n".join(lines))
    print("\n".join(lines))
    print(f"\nwrote {out}")
    open(os.path.join(HERE, "matrix.json"), "w").write(json.dumps(res["matrix"], indent=2))


if __name__ == "__main__":
    main()
