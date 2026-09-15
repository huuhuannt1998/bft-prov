"""Emit Supplementary Table S3 from canonical_quorums.json.

Reviewer issue 3.1 again, one layer down: the supplementary quorum table was produced by an earlier
analysis run with its own member-set draw, so it disagreed with the main paper's Table II for the same
labelled configuration (homogeneous 3-of-5 read 24.3 there and 19.2 here). This script renders the
supplementary table directly from the canonical grid, so the two tables cannot drift apart again.

Usage: PYTHONPATH=. python -m decorrelation.make_supp_quorum_table > /path/to/table.tex
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(__file__)

SHORT = {"homogeneous": "HOM", "same-family-diff-size": "SFD", "family-diverse": "FD",
         "defense-diverse": "DD", "joint-diverse": "JD", "random": "RND",
         "lowest-ASR": "LOW", "best-security-utility": "BSU", "max-diversity": "MXD"}
ORDER = ["homogeneous", "same-family-diff-size", "family-diverse", "defense-diverse",
         "joint-diverse", "random", "lowest-ASR", "best-security-utility", "max-diversity"]


def pct(v: float, width: int = 4) -> str:
    s = f"{v * 100:.1f}"
    return ("\\phantom{0}" if len(s) < width else "") + s


def main() -> None:
    d = json.load(open(os.path.join(HERE, "canonical_quorums.json")))
    grid, named = d["grid"], {(r["composition"], r["N"], r["q"]): r["id"] for r in d["rows"]}

    panels = {}
    for N in (3, 5, 7):
        rows = []
        for c in ORDER:
            for r in sorted([g for g in grid if g["composition"] == c and g["N"] == N],
                            key=lambda g: g["q"]):
                mark = "$^{\\dagger}$" if (c, N, r["q"]) in named else ""
                ratio = "---" if r["pred"] < 1e-9 else f"{r['ratio']:.2f}"
                rows.append(f"{SHORT[c]}{mark} & {r['q']} & {pct(r['asr'])} & {pct(r['pred'])} "
                            f"& {ratio} & {pct(r['utility'], 5)}")
        panels[N] = rows

    h = max(len(v) for v in panels.values())
    for v in panels.values():
        v += [" & & & & & "] * (h - len(v))

    head = ("Comp. & $q$ & ASR & Pred. & Ratio & Util.")
    print("\\begin{table*}[t]")
    print("\\centering")
    print("\\tiny")
    print("\\setlength{\\tabcolsep}{2.5pt}")
    print("\\caption{All nine composition rules at every threshold, $N \\in \\{3,5,7\\}$, on the held-out "
          "payload half. Every cell is scored from the single canonical member-set draw of "
          "\\texttt{decorrelation/canonical\\_quorums.py}, so a row here and the same configuration in "
          "Table~II of the main paper are the same member sets by construction. A dagger marks a row the "
          "main paper names; member keys for every set are in \\texttt{canonical\\_quorums.json}. "
          "Compositions: HOM homogeneous, SFD same family different size, FD family-diverse, DD "
          "defense-diverse, JD jointly diverse, RND random, LOW lowest training ASR, BSU best training "
          "security-utility, MXD maximum failure-vector diversity. Ratio is ASR over the pooled "
          "independence prediction; ratios below 1 at $q{=}1$ show shared-input dependence helping the "
          "defender when one approval suffices.}")
    print("\\label{s:quorum}")
    print("\\begin{tabular}{@{}llcccc@{\\hspace{9pt}}llcccc@{\\hspace{9pt}}llcccc@{}}")
    print("\\toprule")
    print("\\multicolumn{6}{c}{$N=3$} & \\multicolumn{6}{c}{$N=5$} & \\multicolumn{6}{c}{$N=7$} \\\\")
    print("\\cmidrule(r){1-6}\\cmidrule(lr){7-12}\\cmidrule(l){13-18}")
    print(f"{head} & {head} & {head} \\\\")
    print("\\midrule")
    for i in range(h):
        print(f"{panels[3][i]} & {panels[5][i]} & {panels[7][i]} \\\\")
    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\end{table*}")


if __name__ == "__main__":
    main()
