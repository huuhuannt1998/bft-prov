#!/usr/bin/env python3
"""
PQ-BFT-Prov — Task 4 (RQ1): concrete quantum forgery of a CLASSICAL provenance signature.

Pipeline (Qiskit Aer SIMULATOR ONLY — no real/paid QPU, per scope_boundaries):
  1. Shor period-finding on a TOY modulus N = 15 (a = 7) on AerSimulator -> recover r = 4.
  2. From r, factor N = 3 x 5  ==>  recover phi(N)  ==>  recover the RSA PRIVATE key d
     from the PUBLIC key (N, e). This is the concrete analogue of the Tamarin
     `Shor_break_classical` rule, whose `!ShorOracle(pkC(sk), sk)` returns the secret key
     given only the public key.
  3. Use d to FORGE a textbook-RSA signature on a smart-home provenance/actuation record
     ("unlock_front_door | <nonce>") that the classical verifier ACCEPTS — an actuation the
     honest agent never decided. This is RQ1's concrete side; attribution_classical.spthy is
     its symbolic mirror (P1 & P3 falsified, forgery_reachable verified).

TOY-SCALE HONESTY: N = 15 is a 4-bit modulus. The simulator cannot factor a real 2048-bit RSA
modulus; the demo shows the MECHANISM (public key -> private key -> universal forgery), not a
break of deployed RSA. The point is exactly why the provenance chain must use ML-DSA, not RSA/ECDSA.
"""
from __future__ import annotations
import sys
from fractions import Fraction
from math import gcd
import hashlib

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


# ---------------------------------------------------------------------------
# Quantum part: Shor period-finding for a^x mod 15 (canonical textbook circuit)
# ---------------------------------------------------------------------------
def c_amod15(a: int, power: int):
    """Controlled multiplication by a^(2^power) mod 15 (a in {2,4,7,8,11,13})."""
    if a not in (2, 4, 7, 8, 11, 13):
        raise ValueError("a must be coprime to 15 and in the supported set")
    U = QuantumCircuit(4)
    for _ in range(power):
        if a in (2, 13):
            U.swap(2, 3); U.swap(1, 2); U.swap(0, 1)
        if a in (7, 8):
            U.swap(0, 1); U.swap(1, 2); U.swap(2, 3)
        if a in (4, 11):
            U.swap(1, 3); U.swap(0, 2)
        if a in (7, 11, 13):
            for q in range(4):
                U.x(q)
    gate = U.to_gate()
    gate.name = f"{a}^{2**power} mod 15"
    return gate.control()


def qft_dagger(n: int) -> QuantumCircuit:
    qc = QuantumCircuit(n)
    for q in range(n // 2):
        qc.swap(q, n - q - 1)
    for j in range(n):
        for m in range(j):
            qc.cp(-3.14159265358979 / float(2 ** (j - m)), m, j)
        qc.h(j)
    qc.name = "QFT+"
    return qc


def shor_find_period(a: int = 7, N: int = 15, n_count: int = 8, shots: int = 2048) -> int:
    """Run phase estimation on Aer and recover the period r of a^x mod N."""
    qc = QuantumCircuit(n_count + 4, n_count)
    for q in range(n_count):
        qc.h(q)
    qc.x(n_count)  # work register = |1>
    for q in range(n_count):
        qc.append(c_amod15(a, q), [q] + [n_count + i for i in range(4)])
    qc.append(qft_dagger(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))

    sim = AerSimulator()
    tqc = transpile(qc, sim)
    counts = sim.run(tqc, shots=shots).result().get_counts()

    # Convert each measured phase to a candidate period via continued fractions.
    candidates: dict[int, int] = {}
    for bitstring, c in counts.items():
        decimal = int(bitstring, 2)
        phase = decimal / (2 ** n_count)
        r = Fraction(phase).limit_denominator(N).denominator
        if r:
            candidates[r] = candidates.get(r, 0) + c
    # Standard Shor classical post-processing: a measured phase k/r yields a denominator that is
    # a MULTIPLE of the true period (e.g. 8 instead of 4). Reduce each candidate to its minimal
    # period by checking divisors (uses only measured data), then take the smallest valid period.
    def minimal_period(rr: int) -> int:
        for dd in range(1, rr + 1):
            if rr % dd == 0 and pow(a, dd, N) == 1:
                return dd
        return 0
    periods = {minimal_period(r) for r in candidates if r > 0}
    periods.discard(0)
    return min(periods) if periods else 0


def factor_with_period(a: int, N: int, r: int):
    if r == 0 or r % 2 != 0:
        return None
    x = pow(a, r // 2, N)
    if x == N - 1:
        return None
    p, q = gcd(x - 1, N), gcd(x + 1, N)
    if p * q == N and p not in (1, N) and q not in (1, N):
        return tuple(sorted((p, q)))
    return None


# ---------------------------------------------------------------------------
# Classical part: derive the private key and FORGE a provenance signature
# ---------------------------------------------------------------------------
def modinv(e: int, phi: int) -> int:
    return pow(e, -1, phi)


def toy_rsa_keys(p: int, q: int, e: int):
    N = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} not coprime to phi={phi}")
    d = modinv(e, phi)
    return N, e, d, phi


def record_representative(record: str, N: int) -> int:
    """Hash the actuation record and reduce into Z_N (toy message representative)."""
    h = int.from_bytes(hashlib.sha256(record.encode()).digest(), "big")
    return h % N


def rsa_sign(m: int, d: int, N: int) -> int:
    return pow(m, d, N)


def rsa_verify(m: int, s: int, e: int, N: int) -> bool:
    return pow(s, e, N) == m % N


def main() -> int:
    a, N_quantum = 7, 15
    print("=" * 74)
    print("PQ-BFT-Prov Task 4 (RQ1): quantum forgery of a classical provenance signature")
    print("=" * 74)

    print(f"\n[1] Shor period-finding on Aer simulator: a={a}, N={N_quantum} ...")
    r = shor_find_period(a=a, N=N_quantum)
    print(f"    recovered period r = {r}   (check: {a}^{r} mod {N_quantum} = {pow(a,r,N_quantum)})")

    factors = factor_with_period(a, N_quantum, r)
    if not factors:
        print("    period-finding did not yield factors this run (probabilistic); rerun.")
        return 1
    p, q = factors
    print(f"[2] Factored public modulus: N = {N_quantum} = {p} x {q}  (Shor success)")

    # Toy RSA public key the smart-home provenance chain would have used (classically).
    e = 7
    N, e, d, phi = toy_rsa_keys(p, q, e)
    print(f"    classical provenance PUBLIC key : (N={N}, e={e})")
    print(f"    phi(N) = {phi}  ->  recovered PRIVATE key d = {d}   <-- the secret, from public alone")
    print("    [== Tamarin Shor_break_classical: !ShorOracle(pkC(sk), sk) returns sk ==]")

    # The adversary forges a signature on an actuation the agent NEVER decided.
    forged_record = "actuate:unlock_front_door|agent=home-llm|nonce=0xBADC0DE"
    m = record_representative(forged_record, N)
    s_forged = rsa_sign(m, d, N)  # adversary signs using the Shor-recovered private key
    accepted = rsa_verify(m, s_forged, e, N)

    print(f"\n[3] FORGERY of a provenance record the honest agent never signed:")
    print(f"    record   : {forged_record}")
    print(f"    msg rep m : {m}  (sha256(record) mod N)")
    print(f"    forged sig: {s_forged}")
    print(f"    classical verifier ACCEPTS forged signature: {accepted}")
    if not accepted:
        print("    unexpected: forgery rejected"); return 1

    print("\n[4] Two-level correspondence with the Tamarin classical model:")
    print("    concrete (here)         symbolic (attribution_classical.spthy)")
    print("    ---------------------   --------------------------------------")
    print("    Shor factors N          rule Shor_break_classical / !ShorOracle")
    print("    recover d from (N,e)    Out(skC) given In(pkC(skC))")
    print("    forge sig on record     sig accepted by Guard_Approve_and_Commit")
    print("    verifier accepts        Actuate(A,x) with no AgentDecide(A,x)")
    print("    => P1 & P3 falsified, forgery_reachable verified")
    print("\n    The ML-DSA chain (attribution_pqc.spthy) has NO such oracle -> forgery unreachable.")
    print("\nDONE. Toy modulus only; Aer simulator only; demonstrates the MECHANISM, not a break of real RSA.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
