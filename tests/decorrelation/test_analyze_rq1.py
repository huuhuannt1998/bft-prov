import math
import random

import numpy as np

from decorrelation.analyze_rq1 import (
    _rows_from_cells,
    build_dataframe,
    build_dataframe_from_rows,
    defense_vs_family_contrast,
    fit_glmm,
)
from decorrelation.model_matrix import MATRIX

def _synthetic_rows(n=1200, seed=0):
    rng = random.Random(seed)
    rows = []
    fams = ["llama","qwen","mistral","gemma"]
    defs = ["none","provenance"]
    for i in range(n):
        fam = rng.choice(fams); dfn = rng.choice(defs)
        payload = f"p{i % 60}"; model = f"{fam}-m"
        # planted: 'none' defense approves injections far more than 'provenance'
        base = 0.6 if dfn == "none" else 0.05
        approve = 1 if rng.random() < base else 0
        rows.append({"approve": approve, "family": fam, "size_b": 0.0, "defense": dfn,
                     "attack_category": "forged-user-auth", "delivery": "indirect",
                     "payload": payload, "model": model})
    return rows

def test_glmm_recovers_defense_sign():
    df = build_dataframe_from_rows(_synthetic_rows())
    res = fit_glmm(df)
    # the fixed-effect coefficient for defense[provenance] must be strongly negative vs 'none'
    params = res.fe_mean if hasattr(res, "fe_mean") else res.params
    names = list(res.model.exog_names)
    idx = [i for i,n in enumerate(names) if "provenance" in n.lower()]
    assert idx, f"no provenance term in {names}"
    assert float(params[idx[0]]) < -0.5


def test_size_b_is_standardized_log_params():
    """preregistration.md §3: size_b = (log(params) - mean(log(params))) / sd(log(params)),
    computed over the RQ1 model matrix (MATRIX). GLMM-free: exercises _rows_from_cells's
    standardization directly via build_dataframe, using two real MATRIX tags of different
    param sizes and real injected cids from build_tdsc_corpus so _rows_from_cells doesn't
    skip them."""
    tag_big, tag_small = "llama3.1:8b", "qwen2.5:3b"
    params_big = next(m.params for m in MATRIX if m.tag == tag_big)
    params_small = next(m.params for m in MATRIX if m.tag == tag_small)
    assert params_big != params_small  # sanity: must be different sizes to see nonzero variance

    lps = [math.log(m.params) for m in MATRIX]
    mean_lp = np.mean(lps)
    sd_lp = np.std(lps)
    expected_big = (math.log(params_big) - mean_lp) / sd_lp
    expected_small = (math.log(params_small) - mean_lp) / sd_lp

    # real injected cids (forged-user-auth is present in build_tdsc_corpus, see fua-0.. above)
    cids = ["fua-0", "fua-1"]
    cells = [
        {"tag": tag_big, "defense": "none", "injected": {c: True for c in cids},
         "raw": {c: [True, True, True] for c in cids}},
        {"tag": tag_small, "defense": "none", "injected": {c: False for c in cids},
         "raw": {c: [False, False, False] for c in cids}},
    ]
    df = build_dataframe(cells)
    assert not df.empty, "expected non-empty dataframe from real MATRIX tags + real cids"

    got_big = df.loc[df["model"] == tag_big, "size_b"].unique()
    got_small = df.loc[df["model"] == tag_small, "size_b"].unique()
    assert len(got_big) == 1 and len(got_small) == 1
    assert abs(float(got_big[0]) - expected_big) < 1e-9
    assert abs(float(got_small[0]) - expected_small) < 1e-9

    # standardization must not collapse different sizes to the same value
    assert df["size_b"].nunique() > 1
    assert df["size_b"].var() > 0

    # I3: unit of observation is one (model, defense, case, rep) vote (preregistration.md §2) --
    # 2 cids x 3 reps per cell, so the dataframe must have 6 rows per cell, not 2.
    assert (df["model"] == tag_big).sum() == 6
    assert (df["model"] == tag_small).sum() == 6


def test_rows_from_cells_emit_one_row_per_rep():
    """preregistration.md §2: 'the unit of observation is one (model, defense, case, rep) vote --
    Every row in the RQ1 dataset is one such vote.' _rows_from_cells must emit one row per raw
    per-rep vote (cell['raw'][cid]), not one row per modal vote (cell['injected'][cid])."""
    cell = {
        "tag": "llama3.2:3b", "defense": "none",
        "injected": {"fua-0": True, "fua-1": False},
        "raw": {"fua-0": [True, True, False], "fua-1": [False, False, False]},
    }
    rows = _rows_from_cells([cell])
    assert len(rows) == 6  # 3 reps x 2 cids

    approvals_fua0 = sorted(r["approve"] for r in rows if r["payload"] == "fua-0")
    assert approvals_fua0 == [0, 1, 1]
    approvals_fua1 = [r["approve"] for r in rows if r["payload"] == "fua-1"]
    assert approvals_fua1 == [0, 0, 0]

    # the modal 'injected' value is NOT what's emitted -- e.g. fua-0's modal is True (2/3) but
    # both the True and the dissenting False rep must appear, not just the modal True x N.
    assert 0 in approvals_fua0 and 1 in approvals_fua0


def test_rows_from_cells_falls_back_to_modal_when_raw_missing():
    """Defensive fallback: if a cell lacks 'raw' for a cid, emit a single row from the modal
    'injected' value rather than crashing or silently dropping the cid."""
    cell = {
        "tag": "llama3.2:3b", "defense": "none",
        "injected": {"fua-0": True},
        "raw": {},
    }
    rows = _rows_from_cells([cell])
    assert len(rows) == 1
    assert rows[0]["approve"] == 1
    assert rows[0]["payload"] == "fua-0"


def test_defense_vs_family_contrast_recovers_planted_direction():
    """preregistration.md §4: primary contrast delta = phi_family-diverse - phi_defense-diverse,
    pooled over ALL qualifying replica pairs (defense-diverse = same family, different defense;
    family-diverse = same defense, different family), with a joint payload bootstrap CI.

    Plant: cell1 (llama3.1:8b, d1) and cell3 (qwen2.5:7b, d1) are family-diverse (same defense d1,
    different family llama/qwen) and co-approve in lockstep (phi = +1). cell1 and cell2
    (llama3.2:3b, d2) are defense-diverse (same family llama, different defense d1/d2) and are
    anti-correlated (phi = -1). Recovered delta must be positive."""
    payloads = [f"p{i}" for i in range(8)]
    pattern = [True, True, True, True, False, False, False, False]
    anti = [not v for v in pattern]

    cells = [
        {"tag": "llama3.1:8b", "defense": "d1", "injected": dict(zip(payloads, pattern))},
        # defense-diverse w/ cell[0]: same family (llama), different defense (d1 vs d2)
        {"tag": "llama3.2:3b", "defense": "d2", "injected": dict(zip(payloads, anti))},
        # family-diverse w/ cell[0]: same defense (d1), different family (llama vs qwen)
        {"tag": "qwen2.5:7b", "defense": "d1", "injected": dict(zip(payloads, pattern))},
    ]

    out = defense_vs_family_contrast(cells)
    for key in ("delta", "ci_lo", "ci_hi", "phi_family_diverse", "phi_defense_diverse"):
        assert key in out, f"missing key {key} in {out}"

    assert out["phi_family_diverse"] == 1.0
    assert out["phi_defense_diverse"] == -1.0
    assert out["delta"] == out["phi_family_diverse"] - out["phi_defense_diverse"]
    assert out["delta"] > 0
    assert out["ci_lo"] is not None and out["ci_hi"] is not None


def test_defense_vs_family_contrast_handles_no_qualifying_pairs():
    """Sparse-data path (no crash): a single cell has no qualifying defense- or family-diverse
    partner, so the function must return an informative dict, not raise."""
    cells = [{"tag": "llama3.1:8b", "defense": "d1", "injected": {"p0": True, "p1": False}}]
    out = defense_vs_family_contrast(cells)
    assert out["delta"] is None
    assert out["phi_family_diverse"] is None
    assert out["phi_defense_diverse"] is None
