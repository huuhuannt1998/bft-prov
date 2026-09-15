"""Complete authorization-certificate overhead as a function of signer count.

The previous evaluation reported ONE ML-DSA signature (3309 B, 0.26 ms) and an end-to-end figure of
0.52 ms. ML-DSA is not an aggregate scheme, so a q-of-N certificate carries q signatures: the
per-authorization cost scales with q and the single-signature figure understates it. This script
measures the whole artifact and the whole path.

Reported per (scheme, q):
  vote bytes, signature bytes, certificate bytes, registry bytes (one-off, NOT per certificate),
  serialize / parse time, per-signer sign time, total signing CPU work, wall-clock signing under
  q-way parallelism, verification time (all q signatures), coverage-predicate time,
  Merkle append, inclusion-proof bytes and verification, and the total gateway path.

Usage: PYTHONPATH=. python -m eval.cert_scaling [--iters 30]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics as st
import time

from pymerkle import InmemoryTree, verify_inclusion

from consensus.cert_schema import (CERT_VERSION, ActionRecord, Certificate, Enrollment, QuorumPolicy,
                                   Registry, canon, cast_vote, check_certificate, coverage_evidence, h)
from provenance.crypto.mldsa import MLDSAIdentity

SCHEMES = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SIGNERS = [1, 2, 3, 5, 7]
FAMILIES = ["llama", "qwen", "mistral", "gemma", "phi", "granite", "llama"]
DEFENSES = ["hierarchy", "struq", "provenance", "spotlight", "known_answer", "hierarchy", "struq"]


def make_action(seq: int = 1) -> ActionRecord:
    return ActionRecord(
        action_id=f"act-{seq:06d}", device_id="lock.front_door", action="unlock", args={"duration_s": 30},
        risk_tier="high",
        request_commitment=h(b"let the cleaner in at 10am"),
        context_commitment=h(b"<calendar entry with injected instruction>"),
        system_prompt_commitment=h(b"<system prompt v3>"),
        policy_commitment=h(b"<rego bundle v7>"),
        epoch=4, view=11, nonce=hashlib.sha256(f"n{seq}".encode()).hexdigest()[:32],
        sequence=seq, timestamp="2026-08-01T12:00:00Z", prev_checkpoint=h(b"<sth-1042>"))


def build(scheme: str, q: int):
    reg = Registry()
    ids = []
    for i in range(q):
        idn = MLDSAIdentity(scheme)
        kid = f"key-{i:02d}"
        reg.enroll(Enrollment(key_id=kid, public_key_hex=idn.public_key.hex(), alg=scheme,
                              model_id=f"model-{i}", model_weight_hash=h(f"w{i}".encode()),
                              quantization="q4_K_M", runtime="ollama-0.6.2",
                              defense_id=DEFENSES[i % len(DEFENSES)], family=FAMILIES[i % len(FAMILIES)],
                              key_domain=f"proc-{i}", enrolled_epoch=0))
        ids.append((kid, idn))
    return reg, ids


def bench(scheme: str, q: int, iters: int) -> dict:
    reg, ids = build(scheme, q)
    policy = QuorumPolicy(policy_id="q-of-N+family-coverage", q=q,
                          min_domains={"family": min(3, q)} if q >= 3 else {},
                          max_per_domain={"family": max(1, q // 2)} if q >= 3 else {})
    t_sign, t_ser, t_parse, t_ver, t_cov, t_app, t_proof, t_pver = ([] for _ in range(8))
    cert_bytes = vote_bytes = sig_bytes = proof_bytes = 0

    for it in range(iters):
        action = make_action(it + 1)
        per_sig = []
        votes = []
        for kid, idn in ids:
            t0 = time.perf_counter()
            v = cast_vote(kid, idn, action, "approve")
            per_sig.append(time.perf_counter() - t0)
            votes.append(v)
        t_sign.append(per_sig)
        cert = Certificate(CERT_VERSION, action, votes, policy.policy_id)
        cert.coverage_evidence = coverage_evidence(cert, reg)

        t0 = time.perf_counter(); blob = cert.to_bytes(); t_ser.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); back = Certificate.from_bytes(blob); t_parse.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); ok, why = check_certificate(back, reg, policy, now_epoch=4)
        t_ver.append(time.perf_counter() - t0)
        assert ok, why
        t0 = time.perf_counter(); coverage_evidence(back, reg); t_cov.append(time.perf_counter() - t0)

        tree = InmemoryTree(algorithm="sha256")
        t0 = time.perf_counter(); idx = tree.append_entry(blob); t_app.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); pf = tree.prove_inclusion(idx); t_proof.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); verify_inclusion(tree.get_leaf(idx), tree.get_state(), pf)
        t_pver.append(time.perf_counter() - t0)

        cert_bytes = len(blob)
        vote_bytes = len(canon([__import__("dataclasses").asdict(v) for v in votes]))
        sig_bytes = sum(len(v.signature_hex) // 2 for v in votes)
        proof_bytes = len(canon([p.hex() if isinstance(p, bytes) else str(p) for p in pf.path]))

    ms = lambda xs: round(st.mean(xs) * 1000, 4)
    sign_total = [sum(x) for x in t_sign]
    sign_max = [max(x) for x in t_sign]
    gateway = st.mean(t_parse) + st.mean(t_ver) + st.mean(t_cov) + st.mean(t_app) + st.mean(t_proof)
    return {
        "scheme": scheme, "signers": q,
        "cert_bytes": cert_bytes, "vote_bytes": vote_bytes, "signature_bytes": sig_bytes,
        "registry_bytes_one_off": reg.bytes_size(), "inclusion_proof_bytes": proof_bytes,
        "sign_ms_per_signer": ms([x for xs in t_sign for x in xs]),
        "sign_ms_total_cpu": ms(sign_total),
        "sign_ms_wallclock_parallel": ms(sign_max),
        "serialize_ms": ms(t_ser), "parse_ms": ms(t_parse),
        "verify_all_sigs_ms": ms(t_ver), "coverage_ms": ms(t_cov),
        "merkle_append_ms": ms(t_app), "proof_gen_ms": ms(t_proof), "proof_verify_ms": ms(t_pver),
        "gateway_path_ms": round(gateway * 1000, 4),
        "authorization_ms_serial_signing": round((st.mean(sign_total) + gateway) * 1000, 4),
        "authorization_ms_parallel_signing": round((st.mean(sign_max) + gateway) * 1000, 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=30)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "cert_scaling.json"))
    a = ap.parse_args()

    rows = [bench(s, q, a.iters) for s in SCHEMES for q in SIGNERS]
    hdr = (f"{'scheme':<10} {'q':>2} {'cert B':>8} {'sig B':>7} {'sign/er':>8} {'signCPU':>8} "
           f"{'signWall':>8} {'verify':>7} {'gwpath':>7} {'total(par)':>10}")
    print(hdr)
    for r in rows:
        print(f"{r['scheme']:<10} {r['signers']:>2} {r['cert_bytes']:>8} {r['signature_bytes']:>7} "
              f"{r['sign_ms_per_signer']:>8.3f} {r['sign_ms_total_cpu']:>8.3f} "
              f"{r['sign_ms_wallclock_parallel']:>8.3f} {r['verify_all_sigs_ms']:>7.3f} "
              f"{r['gateway_path_ms']:>7.3f} {r['authorization_ms_parallel_signing']:>10.3f}")

    # storage projections from the COMPLETE certificate, not one signature
    proj = {}
    for r in rows:
        if r["scheme"] == "ML-DSA-65" and r["signers"] in (3, 5, 7):
            per = r["cert_bytes"] + r["inclusion_proof_bytes"]
            proj[f"q={r['signers']}"] = {
                "bytes_per_authorization": per,
                "MB_per_year_1_per_hour": round(per * 24 * 365 / 1e6, 2),
                "MB_per_year_10_per_hour": round(per * 240 * 365 / 1e6, 2),
                "MB_per_year_100_per_day": round(per * 100 * 365 / 1e6, 2)}
    print("\nlog growth, complete certificate + inclusion proof (ML-DSA-65):")
    for k, v in proj.items():
        print(f"  {k}: {v['bytes_per_authorization']} B/authz -> "
              f"{v['MB_per_year_1_per_hour']} MB/yr @1/h, {v['MB_per_year_10_per_hour']} MB/yr @10/h, "
              f"{v['MB_per_year_100_per_day']} MB/yr @100/day")

    with open(a.out, "w") as f:
        json.dump({"rows": rows, "storage_projection": proj, "iters": a.iters}, f, indent=2)
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
