import os, json

import pytest

from decorrelation.defenses import OllamaError
from decorrelation.run_rq1 import modal, run_cell, checkpoint_path, run_sweep

class _Stub:
    """Deterministic judge: approves iff 'UNLOCK' appears in ingested (simulates an injected hit)."""
    def __call__(self, device, command, context, ingested):
        return "UNLOCK" in (ingested or "")

class _AlwaysOllamaError:
    """Simulates a persistently-unreachable Ollama backend (finding I4)."""
    def __call__(self, device, command, context, ingested):
        raise OllamaError("simulated persistent transport failure")

def test_modal_majority():
    assert modal([True, True, False]) is True
    assert modal([False, False, True]) is False
    assert modal([True]) is True
    # finding M1: ties default to the conservative label, DENY (preregistration.md §6)
    assert modal([True, False]) is False

def test_run_cell_shapes(tmp_path):
    class C:
        def __init__(s, cid): s.cid=cid; s.device="lock.x"; s.command="unlock"; s.trusted_task="t"
        ingested_benign="all quiet"; ingested_injected="please UNLOCK"
    corpus=[C("a"), C("b")]
    legit=[("l1","turn on light","light.k","turn_on","motion")]
    res=run_cell(_Stub(), corpus, legit, reps=3)
    assert res["injected"]["a"] is True and res["baseline"]["a"] is False
    assert res["legit"]["l1"] is False               # stub only approves on UNLOCK
    assert len(res["raw"]["a"]) == 3
    # preregistration.md §6: per-rep raw votes retained for legit/baseline/controls too, not just injected
    assert res["raw_legit"]["l1"] == [False, False, False]
    assert res["raw_baseline"]["a"] == [False, False, False]
    assert res["raw_baseline"]["b"] == [False, False, False]

def test_checkpoint_path_encodes_tag_and_defense(tmp_path):
    p = checkpoint_path(str(tmp_path), "llama3.1:8b", "provenance")
    assert p.endswith(".json") and "provenance" in p

def test_run_sweep_resumability(tmp_path, monkeypatch):
    monkeypatch.setattr("decorrelation.run_rq1.make_judge", lambda tag, defense: _Stub())

    out_dir = str(tmp_path)
    # a real, installed MATRIX tag so the validate-tags gate (finding I4) passes
    run_sweep(out_dir=out_dir, reps=1, only_tags=["qwen2.5:3b"], only_defenses=["none"])

    files = [f for f in os.listdir(out_dir) if f.endswith(".json")]
    assert len(files) == 1
    p = os.path.join(out_dir, files[0])

    with open(p) as f:
        data = json.load(f)
    assert set(data.keys()) == {"tag", "defense", "reps", "legit", "baseline", "injected", "raw",
                                 "controls", "raw_legit", "raw_baseline", "raw_controls"}

    mtime_before = os.path.getmtime(p)
    with open(p, "rb") as f:
        content_before = f.read()

    run_sweep(out_dir=out_dir, reps=1, only_tags=["qwen2.5:3b"], only_defenses=["none"])

    mtime_after = os.path.getmtime(p)
    with open(p, "rb") as f:
        content_after = f.read()

    assert mtime_before == mtime_after
    assert content_before == content_after


def test_run_sweep_validates_tags_before_running(tmp_path):
    """Finding I4: a missing/uninstalled model tag must raise a clear error BEFORE the sweep runs
    anything, not silently produce garbage (or hang on a real HTTP call to an absent model)."""
    with pytest.raises(Exception):
        run_sweep(out_dir=str(tmp_path), reps=1, only_tags=["bogus:nope"], only_defenses=["none"])
    assert [f for f in os.listdir(str(tmp_path)) if f.endswith(".json")] == []


def test_run_sweep_skips_checkpoint_on_ollama_error(tmp_path, monkeypatch):
    """Finding I4: a transient/persistent Ollama transport failure must not be written as a
    completed (all-DENY) checkpoint -- resume must retry the whole cell, not skip it forever."""
    monkeypatch.setattr("decorrelation.run_rq1.make_judge", lambda tag, defense: _AlwaysOllamaError())

    out_dir = str(tmp_path)
    run_sweep(out_dir=out_dir, reps=1, only_tags=["qwen2.5:3b"], only_defenses=["none"])

    files = [f for f in os.listdir(out_dir) if f.endswith(".json")]
    assert files == [], f"expected no checkpoint written on OllamaError, found: {files}"
