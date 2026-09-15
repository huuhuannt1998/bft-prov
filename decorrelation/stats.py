"""
Statistics for the scaled evaluation (P1 #6/#7). Pure Python (math + random only) so the artifact
reproduces without scipy. All proportions are reported with Wilson 95% score intervals; paired
comparisons use McNemar's exact test; unpaired 2x2 use Fisher's exact; the susceptible-family
co-approval correlation (phi) is reported with a payload-bootstrap 95% CI under a pre-registered rule
that never asserts independence from a point estimate.
"""
from __future__ import annotations
import math
import random

Z95 = 1.959963984540054  # standard normal 97.5th percentile


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float, float]:
    """Wilson score interval for a binomial proportion. Returns (phat, lo, hi)."""
    if n == 0:
        return (0.0, 0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (p, max(0.0, center - half), min(1.0, center + half))


def _log_binom(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _binom_pmf(k: int, n: int, p: float) -> float:
    if k < 0 or k > n:
        return 0.0
    return math.exp(_log_binom(n, k) + k * math.log(p) + (n - k) * math.log(1 - p))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant-pair counts b, c (paired binary).
    Under H0 each discordant pair is a fair coin; p = 2 * P(X <= min(b,c)) over Binom(b+c, 1/2)."""
    n = b + c
    if n == 0:
        return 1.0
    m = min(b, c)
    tail = sum(_binom_pmf(i, n, 0.5) for i in range(0, m + 1))
    return min(1.0, 2.0 * tail)


def fisher_exact(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p for the 2x2 table [[a,b],[c,d]] (sum-of-small-probabilities method)."""
    n = a + b + c + d
    r1, r2, c1 = a + b, c + d, a + c
    def logp(x):  # P(top-left = x) hypergeometric
        return (_log_binom(r1, x) + _log_binom(r2, c1 - x)) - _log_binom(n, c1)
    lo, hi = max(0, c1 - r2), min(r1, c1)
    p_obs = logp(a)
    tot = 0.0
    for x in range(lo, hi + 1):
        lx = logp(x)
        if lx <= p_obs + 1e-9:
            tot += math.exp(lx)
    return min(1.0, tot)


def phi_coeff(pairs: list[tuple[int, int]]) -> float | None:
    """Matthews/phi correlation for a list of (a,b) binary observations; None if a margin is degenerate."""
    n = len(pairs)
    if n == 0:
        return None
    sa = sum(a for a, _ in pairs)
    sb = sum(b for _, b in pairs)
    if sa in (0, n) or sb in (0, n):
        return None
    n11 = sum(1 for a, b in pairs if a and b)
    num = n * n11 - sa * sb
    den = math.sqrt(sa * (n - sa) * sb * (n - sb))
    return num / den if den else None


def bootstrap_phi(pairs: list[tuple[int, int]], B: int = 10000, seed: int = 12345) -> dict:
    """Payload-bootstrap 95% CI for phi. Resamples payloads with replacement; degenerate resamples
    (a family constant) are recorded as 'undefined' and excluded from the percentile, with their fraction
    reported so the reader sees how often phi is even defined."""
    rng = random.Random(seed)
    n = len(pairs)
    point = phi_coeff(pairs)
    vals = []
    undef = 0
    for _ in range(B):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        v = phi_coeff(sample)
        if v is None:
            undef += 1
        else:
            vals.append(v)
    vals.sort()
    def pct(q):
        if not vals:
            return None
        i = min(len(vals) - 1, max(0, int(q * (len(vals) - 1))))
        return vals[i]
    return {"point": point, "lo": pct(0.025), "hi": pct(0.975),
            "undefined_frac": undef / B, "n_defined": len(vals)}


def interpret_phi(bs: dict, meaningful: float = 0.2) -> str:
    """Pre-registered decision rule (#7): never assert independence from a point estimate.
    - if the CI reaches into meaningful positive correlation -> insufficient evidence for independence;
    - if the CI is tight around 0 (|hi|,|lo| < meaningful) -> evidence against same-payload co-failure."""
    lo, hi = bs.get("lo"), bs.get("hi")
    if lo is None or hi is None:
        return "phi undefined too often to interpret (report the undefined fraction)"
    if hi >= meaningful:
        return ("insufficient evidence for same-payload correlated failure in this sample "
                "(CI admits meaningful positive correlation; we do NOT assert independence)")
    if abs(lo) < meaningful and abs(hi) < meaningful:
        return ("CI tight around zero: evidence against same-payload co-failure "
                "(reported as phi with CI, not as an independence assertion)")
    return "phi CI in the negative/near-zero range; report verbatim with the caveat that n bounds power"


def fmt_ci(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} = {p*100:.0f}% [{lo*100:.0f}, {hi*100:.0f}]"
