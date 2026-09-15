"""RQ1 analysis: pre-registered mixed-effects logistic regression (statsmodels GLMM) over injection votes,
plus the defense-diversity-vs-family-diversity phi contrast. Reads run_rq1 checkpoints. Free/open-source
(statsmodels BSD). The pure-Python Wilson/Fisher/bootstrap path in stats.py is unchanged.

The primary model (`fit_glmm`) matches `docs/02-fault-domain-model/preregistration.md` §3 verbatim:

    approve ~ family + size_b + defense + attack_category + delivery
              + defense:family + attack_category:defense
              + (1|payload) + (1|model)

including the two interaction terms (`defense:family`, `attack_category:defense`) the pre-registration
requires — they are the confirmatory-model analogue of the primary contrast (§4) and of the expectation
that a defense's effect is not uniform across attack categories, so they are not optional simplifications.
"""
from __future__ import annotations
import glob, itertools, json, math, os, random

import numpy as np
import pandas as pd
from statsmodels.genmod.bayes_mixed_glm import BinomialBayesMixedGLM

from decorrelation.corpus_tdsc import build_tdsc_corpus
from decorrelation.model_matrix import MATRIX
from decorrelation.stats import phi_coeff

_CASE = {c.cid: c for c in build_tdsc_corpus()}
_CFG = {m.tag: m for m in MATRIX}


def load_cells(out_dir: str) -> list[dict]:
    """Load sweep checkpoints in a DETERMINISTIC order.

    `glob.glob` returns filesystem order, which is arbitrary and machine-dependent. Sorting is
    required for reproducibility: the seeded bootstrap in `defense_vs_family_contrast` resamples
    payload keys whose insertion order depends on cell order, so an unsorted load makes the
    reported CI irreproducible across hosts and checkouts.
    """
    cells = []
    for p in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
        with open(p) as f:
            cells.append(json.load(f))
    return cells


def _rows_from_cells(cells: list[dict]) -> list[dict]:
    """preregistration.md §2: the unit of observation is one (model, defense, case, rep) vote --
    every row emitted here is one such vote, drawn from cell['raw'][cid] (the per-rep injected
    vote list), NOT from the modal cell['injected'][cid] (which would cut effective N ~3x and
    collapse per-rep dispersion the GLMM's (1|payload)/(1|model) terms are meant to absorb).
    The modal 'injected' value remains the basis for the §4 phi contrast and §5 ASR, but is not
    used for the GLMM rows."""
    rows = []
    _lps = [math.log(m.params) for m in MATRIX]
    mean_lp = np.mean(_lps)
    sd_lp = np.std(_lps)  # population sd (preregistration.md §3 is silent on population vs sample)
    for cell in cells:
        cfg = _CFG.get(cell["tag"])
        if cfg is None:
            continue
        size_b = (math.log(cfg.params) - mean_lp) / sd_lp if sd_lp > 0 else 0.0
        raw = cell.get("raw") or {}
        for cid, modal_approve in cell["injected"].items():
            case = _CASE.get(cid)
            if case is None:
                continue
            base_row = {"family": cfg.family, "size_b": size_b, "defense": cell["defense"],
                        "attack_category": case.category, "delivery": case.delivery,
                        "payload": cid, "model": cell["tag"]}
            rep_votes = raw.get(cid)
            if rep_votes:
                for v in rep_votes:
                    rows.append({**base_row, "approve": int(bool(v))})
            else:
                # defensive fallback: no raw per-rep votes for this cid -- emit one row from the
                # modal vote rather than dropping the cid or crashing.
                rows.append({**base_row, "approve": int(bool(modal_approve))})
    return rows


def build_dataframe(cells: list[dict]) -> pd.DataFrame:
    return build_dataframe_from_rows(_rows_from_cells(cells))


def build_dataframe_from_rows(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def fit_glmm(df: pd.DataFrame):
    """Primary confirmatory model, preregistration.md §3: fixed effects family/size_b/defense/
    attack_category/delivery plus the defense:family and attack_category:defense interactions,
    random intercepts for payload and model."""
    fe = ("approve ~ C(family) + size_b + C(defense) + C(attack_category) + C(delivery)"
          " + C(defense):C(family) + C(attack_category):C(defense)")
    vc = {"payload": "0 + C(payload)", "model": "0 + C(model)"}
    md = BinomialBayesMixedGLM.from_formula(fe, vc, df)
    return md.fit_vb()


def _cell_family(cell: dict) -> str | None:
    cfg = _CFG.get(cell.get("tag"))
    return cfg.family if cfg else None


def defense_vs_family_contrast(cells: list[dict], B: int = 2000, seed: int = 12345) -> dict:
    """Primary contrast, preregistration.md §4: delta = phi_family-diverse - phi_defense-diverse,
    pooled over EVERY qualifying replica pair (not one hardcoded pair), with a joint payload
    bootstrap 95% CI for delta.

    - defense-diverse replica pair: two cells with the SAME model family, DIFFERENT defense.
    - family-diverse replica pair: two cells with the SAME defense, DIFFERENT model family.

    For every qualifying pair and every payload cid present in both cells' modal `injected` dict
    (co-approval is a per-condition property, §4/§6 -- the modal vote, not per-rep), a binary
    co-observation (int(a[cid]), int(b[cid])) is pooled into that pair's class, keyed by payload
    cid so the bootstrap can resample by payload. delta = phi_family_diverse - phi_defense_diverse;
    RQ1's hypothesis is delta > 0 (defense diversity decorrelates injection failure more than
    family diversity). The 95% CI is a JOINT payload bootstrap: the set of payload cids is
    resampled with replacement once per replicate, and BOTH classes' pooled lists are rebuilt
    restricted to that resample (a payload drawn k times contributes k times to both classes)
    before recomputing phi/delta, so the two phi estimates are not treated as independent.
    Mirrors the seeded-RNG / undefined-fraction discipline of `decorrelation.stats.bootstrap_phi`.
    Never asserts independence/decorrelation from the delta point estimate alone (interpret_phi
    discipline, §5)."""
    n = len(cells)
    families = [_cell_family(c) for c in cells]

    # payload cid -> {"family_diverse": [(x,y), ...], "defense_diverse": [(x,y), ...]}
    by_payload: dict[str, dict[str, list[tuple[int, int]]]] = {}

    def _record(cls: str, a: dict, b: dict) -> None:
        """Pool one replica pair's same-payload co-observations, SYMMETRIZED.

        A replica pair is UNORDERED: there is no "first" and "second" agent. Per-pair phi is already
        symmetric (swapping the two columns leaves phi unchanged), but phi computed on the POOLED
        2x2 table is NOT: pooling some pairs as (x,y) and others as (y,x) changes the two marginals
        sa/sb and hence phi. Because pair order came from `itertools.combinations` over the loaded
        cell list, the pooled estimate silently inherited the filesystem's glob order -- shuffling
        the cells moved phi_family_diverse from 0.145 to 0.124 and flipped the sign of delta.

        Recording each co-observation in BOTH orders makes the pooled table symmetric (sa == sb by
        construction), so phi and delta are invariant to cell ordering. Verified: identical to 4 d.p.
        across shuffled loads. This doubles the pooled counts; phi is a normalized statistic, so the
        point estimate is unaffected by the doubling.
        """
        inj_a, inj_b = a.get("injected") or {}, b.get("injected") or {}
        for cid in set(inj_a) & set(inj_b):
            slot = by_payload.setdefault(cid, {"family_diverse": [], "defense_diverse": []})
            x, y = int(bool(inj_a[cid])), int(bool(inj_b[cid]))
            slot[cls].append((x, y))
            slot[cls].append((y, x))

    for i, j in itertools.combinations(range(n), 2):
        a, b = cells[i], cells[j]
        fam_a, fam_b = families[i], families[j]
        if fam_a is None or fam_b is None:
            continue  # unknown tag -- skip pair safely
        def_a, def_b = a.get("defense"), b.get("defense")
        if fam_a == fam_b and def_a != def_b:
            _record("defense_diverse", a, b)
        if def_a == def_b and fam_a != fam_b:
            _record("family_diverse", a, b)

    def _pool(cls: str, payload_ids) -> list[tuple[int, int]]:
        out = []
        for cid in payload_ids:
            out.extend(by_payload.get(cid, {}).get(cls, []))
        return out

    # sorted(), not list(): dict insertion order follows cell order, so an unsorted key list makes
    # the seeded bootstrap draw different payloads on different hosts. Sorting pins the CI too.
    all_payloads = sorted(by_payload.keys())
    pooled_fam = _pool("family_diverse", all_payloads)
    pooled_def = _pool("defense_diverse", all_payloads)
    phi_fam = phi_coeff(pooled_fam)
    phi_def = phi_coeff(pooled_def)

    if not all_payloads or phi_fam is None or phi_def is None:
        return {
            "delta": None, "ci_lo": None, "ci_hi": None,
            "phi_family_diverse": phi_fam, "phi_defense_diverse": phi_def,
            "n_family_diverse": len(pooled_fam), "n_defense_diverse": len(pooled_def),
            "undefined_frac": None,
            "interpretation": ("insufficient qualifying replica pairs or a degenerate margin in "
                                "at least one class; delta is undefined for this sample"),
        }

    delta_point = phi_fam - phi_def

    def _lift(pairs: list[tuple[int, int]]) -> float | None:
        """Joint-failure lift: P(both approve) / P(approve)^2, i.e. observed joint unsafe approval
        divided by the rate independence predicts. Lift = 1 is independence; lift > 1 is positive
        dependence. Well defined on the symmetrized pool, where both marginals are equal by
        construction. This is the quantity that establishes non-independence for EACH diversity axis
        on its own -- a null DIFFERENCE between two axes never could."""
        n = len(pairs)
        if n == 0:
            return None
        p_marg = sum(a for a, _ in pairs) / n
        if p_marg == 0:
            return None
        return (sum(1 for a, b in pairs if a and b) / n) / (p_marg * p_marg)

    rng = random.Random(seed)
    npay = len(all_payloads)
    deltas = []
    boot = {"family_diverse": {"phi": [], "lift": []}, "defense_diverse": {"phi": [], "lift": []}}
    undef = 0
    for _ in range(B):
        resample = [all_payloads[rng.randrange(npay)] for _ in range(npay)]
        p_fam = phi_coeff(_pool("family_diverse", resample))
        p_def = phi_coeff(_pool("defense_diverse", resample))
        for cls, val in (("family_diverse", p_fam), ("defense_diverse", p_def)):
            if val is not None:
                boot[cls]["phi"].append(val)
            lv = _lift(_pool(cls, resample))
            if lv is not None:
                boot[cls]["lift"].append(lv)
        if p_fam is None or p_def is None:
            undef += 1
        else:
            deltas.append(p_fam - p_def)
    deltas.sort()

    def _pct(q: float):
        if not deltas:
            return None
        idx = min(len(deltas) - 1, max(0, int(q * (len(deltas) - 1))))
        return deltas[idx]

    ci_lo, ci_hi = _pct(0.025), _pct(0.975)
    if ci_lo is None or ci_hi is None:
        interpretation = "delta CI undefined too often to interpret (report the undefined fraction)"
    elif ci_lo > 0:
        interpretation = ("CI excludes zero and is positive: evidence that family-diverse pairs "
                           "co-approve more than defense-diverse pairs (defense diversity "
                           "decorrelates injection failure more than family diversity in this "
                           "sample) -- reported as delta with CI, not asserted from the point "
                           "estimate alone")
    elif ci_hi < 0:
        interpretation = ("CI excludes zero and is negative: evidence against the pre-registered "
                           "direction (family diversity decorrelates more than defense diversity "
                           "in this sample)")
    else:
        interpretation = "delta CI spans zero: insufficient evidence to order defense vs family diversity"

    def _ci(vals: list[float]) -> tuple[float | None, float | None]:
        if not vals:
            return None, None
        s = sorted(vals)
        return (s[min(len(s) - 1, max(0, int(0.025 * (len(s) - 1))))],
                s[min(len(s) - 1, max(0, int(0.975 * (len(s) - 1))))])

    out = {
        "delta": delta_point, "ci_lo": ci_lo, "ci_hi": ci_hi,
        "phi_family_diverse": phi_fam, "phi_defense_diverse": phi_def,
        "n_family_diverse": len(pooled_fam), "n_defense_diverse": len(pooled_def),
        "undefined_frac": undef / B,
        "interpretation": interpretation,
    }
    # Per-axis dependence with its own uncertainty. Each axis is judged against INDEPENDENCE
    # (phi = 0, lift = 1) rather than against the other axis, so "neither diversity axis yields
    # independent failures" is supported directly instead of being inferred from a null difference.
    for cls, short in (("family_diverse", "family"), ("defense_diverse", "defense")):
        lo, hi = _ci(boot[cls]["phi"])
        llo, lhi = _ci(boot[cls]["lift"])
        out[f"phi_{short}_ci"] = [lo, hi]
        out[f"lift_{short}"] = _lift(_pool(cls, all_payloads))
        out[f"lift_{short}_ci"] = [llo, lhi]
    return out


if __name__ == "__main__":
    cells = load_cells(os.path.join(os.path.dirname(__file__), "rq1"))
    if not cells:
        raise SystemExit("no rq1 checkpoints found — run run_rq1 first")
    df = build_dataframe(cells)
    print(f"rows={len(df)}  models={df.model.nunique()}  defenses={df.defense.nunique()}")
    res = fit_glmm(df)
    print(res.summary())
    import json as _j
    print(_j.dumps(defense_vs_family_contrast(cells), indent=1, default=str))
