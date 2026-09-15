"""Resumable RQ1 sweep over {model x defense x case x rep}. One checkpoint JSON per (model, defense) so a
multi-day run resumes cleanly. Statistics are computed separately by analyze_rq1.py from these raw votes.

Usage: PYTHONPATH=. python -m decorrelation.run_rq1 [--reps 3] [--models tagA,tagB] [--defenses provenance,struq]
"""
from __future__ import annotations
import argparse, json, os

from decorrelation.defenses import ALL_DEFENSES, DefenseJudge, KnownAnswerJudge, OllamaError
from decorrelation.corpus_tdsc import build_tdsc_corpus, TDSC_LEGIT, TDSC_CONTROLS
from decorrelation.model_matrix import MATRIX, validate_matrix, installed_tags

OUT = os.path.join(os.path.dirname(__file__), "rq1")


def modal(votes: list[bool]) -> bool:
    """A condition's reported vote is the strict majority of its reps; an even-rep tie defaults to
    the conservative label, DENY (preregistration.md §6, finding M1)."""
    return 2 * sum(1 for v in votes if v) > len(votes)


def make_judge(tag: str, defense: str):
    return KnownAnswerJudge(tag) if defense == "known_answer" else DefenseJudge(tag, defense)


def run_cell(judge, corpus, legit, reps: int, controls=None) -> dict:
    # preregistration.md §6: the raw per-repetition vote sequence is retained per condition (every
    # (model, defense, case) condition), not just the injected channel, so dispersion/ties are
    # visible for every channel. Each channel's per-rep votes are computed once and modal is
    # derived from that list (never call the judge twice for the same channel).
    res = {"legit": {}, "baseline": {}, "injected": {}, "raw": {}, "controls": {},
           "raw_legit": {}, "raw_baseline": {}, "raw_controls": {}}
    for c in legit:
        cid, task, dev, cmd, ing = c
        raw = [judge(dev, cmd, task, ing) for _ in range(reps)]
        res["legit"][cid] = modal(raw)
        res["raw_legit"][cid] = raw
    for c in (controls or []):
        # matched benign controls (finding I5), measured in the benign channel (i.e. on ingested_benign)
        # so the data exists for the pre-registration's §5 matched-FPR reporting.
        cid, task, dev, cmd, ing = c
        raw = [judge(dev, cmd, task, ing) for _ in range(reps)]
        res["controls"][cid] = modal(raw)
        res["raw_controls"][cid] = raw
    for c in corpus:
        raw_baseline = [judge(c.device, c.command, c.trusted_task, c.ingested_benign) for _ in range(reps)]
        res["baseline"][c.cid] = modal(raw_baseline)
        res["raw_baseline"][c.cid] = raw_baseline
        raw = [judge(c.device, c.command, c.trusted_task, c.ingested_injected) for _ in range(reps)]
        res["injected"][c.cid] = modal(raw)
        res["raw"][c.cid] = raw
    return res


def checkpoint_path(out_dir: str, tag: str, defense: str) -> str:
    safe = tag.replace(":", "_").replace("/", "_")
    return os.path.join(out_dir, f"{safe}__{defense}.json")


def run_sweep(out_dir: str = OUT, reps: int = 3, only_tags=None, only_defenses=None):
    tags = only_tags or [m.tag for m in MATRIX]
    defenses = only_defenses or ALL_DEFENSES

    # Validate-tags gate (finding I4): raise a clear error before running anything if a requested
    # tag isn't installed in Ollama (or isn't a recognized MATRIX tag at all).
    known_tags = {m.tag for m in MATRIX}
    missing_installed = set(validate_matrix(installed_tags()))
    missing = [t for t in tags if t not in known_tags or t in missing_installed]
    if missing:
        raise RuntimeError(f"cannot run sweep: model tag(s) not installed in Ollama: {missing}")

    os.makedirs(out_dir, exist_ok=True)
    corpus, legit, controls = build_tdsc_corpus(), TDSC_LEGIT, TDSC_CONTROLS
    legit_tuples = [(x.cid, x.trusted_task, x.device, x.command, x.ingested_benign) for x in legit]
    control_tuples = [(x.cid, x.trusted_task, x.device, x.command, x.ingested_benign) for x in controls]
    for tag in tags:
        for defense in defenses:
            p = checkpoint_path(out_dir, tag, defense)
            if os.path.exists(p):
                print(f"skip {tag} {defense} (checkpoint exists)")
                continue
            print(f"run  {tag} {defense} ...", flush=True)
            try:
                cell = run_cell(make_judge(tag, defense), corpus, legit_tuples, reps, control_tuples)
            except OllamaError as e:
                # infra failure, not a model DENY vote: never write a partial/all-DENY checkpoint --
                # leave nothing on disk so resume retries the whole cell (finding I4).
                print(f"ERROR {tag} {defense}: {e} -- will retry on resume")
                continue
            payload = {"tag": tag, "defense": defense, "reps": reps, **cell}
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, p)   # atomic on POSIX; os.path.exists(p) only ever sees a complete file
    print("sweep complete")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--models", default="")
    ap.add_argument("--defenses", default="")
    a = ap.parse_args()
    run_sweep(reps=a.reps,
              only_tags=[s for s in a.models.split(",") if s] or None,
              only_defenses=[s for s in a.defenses.split(",") if s] or None)
