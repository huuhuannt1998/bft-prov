"""
Task 5 latency benchmark (RQ3). Measures, on the MacBook M4 hub:
  (1) ML-DSA-44/65/87 sign + verify latency (the PQC provenance primitive);
  (2) Merkle-log commit + inclusion-proof latency;
  (3) end-to-end provenance-to-emulated-actuation latency, broken down by stage.

REPORTING HONESTY (dec_01KVWZV01Z23GWW41451NH96X6): the M4 is a capable hub; these numbers are
"feasibility on a capable hub," NOT a constrained-home-device measurement, and the actuation is an
EMULATED Home Assistant virtual device. Writes results.md.
"""
from __future__ import annotations
import os
import statistics as stats
import time

import oqs
from provenance.crypto.mldsa import MLDSAIdentity, verify, PARAMS
from provenance.gateway.record import ActuationIntent, build_record
from provenance.log.merkle_log import ProvenanceLog
from actuation.homeassistant.virtual_device import HAVirtualDevice
from agent.guard.guard import evaluate as guard_evaluate

HERE = os.path.dirname(__file__)


def _timeit(fn, iters: int) -> tuple[float, float]:
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)  # ms
    return stats.mean(samples), stats.median(samples)


def bench_mldsa(iters: int = 300) -> list[dict]:
    rows = []
    msg = b"PQ-BFT-Prov|actuate:input_boolean.front_door|turn_on|nonce=deadbeef"
    for alg in PARAMS:
        with MLDSAIdentity(alg) as ident:
            pk = ident.public_key
            sig_holder = {}
            def do_sign():
                sig_holder["s"] = ident.sign(msg)
            s_mean, s_med = _timeit(do_sign, iters)
            sig = ident.sign(msg)
            def do_verify():
                verify(alg, msg, sig, pk)
            v_mean, v_med = _timeit(do_verify, iters)
            rows.append({"alg": alg, "pk": len(pk), "sig": len(sig),
                         "sign_ms": s_mean, "sign_med": s_med,
                         "verify_ms": v_mean, "verify_med": v_med})
    return rows


def bench_log(iters: int = 300) -> dict:
    rec_id = MLDSAIdentity("ML-DSA-65")
    log = ProvenanceLog()
    def do_commit():
        intent = ActuationIntent(device="light.kitchen", command="turn_on", context_hash="abc")
        rec = build_record("agent", rec_id.public_key, "ML-DSA-65", intent, "permit")
        entry = log.commit(rec, rec_id.sign(rec.signing_bytes()))
        log.prove_and_verify_inclusion(entry)
    mean, med = _timeit(do_commit, iters)
    rec_id.close()
    return {"commit_incl_ms": mean, "commit_incl_med": med}


def bench_end_to_end(iters: int = 50) -> dict:
    # Component breakdown for one permitted actuation.
    ident = MLDSAIdentity("ML-DSA-65")
    log = ProvenanceLog()
    dev = HAVirtualDevice()
    guard_t, sign_t, commit_t, verify_t, act_t = [], [], [], [], []
    for i in range(iters):
        intent = ActuationIntent(device="light.kitchen", command="turn_on", context_hash=f"c{i}")
        t = time.perf_counter(); d = guard_evaluate(intent.device, intent.command); guard_t.append((time.perf_counter()-t)*1e3)
        rec = build_record("agent", ident.public_key, "ML-DSA-65", intent, d)
        t = time.perf_counter(); sig = ident.sign(rec.signing_bytes()); sign_t.append((time.perf_counter()-t)*1e3)
        t = time.perf_counter(); entry = log.commit(rec, sig); commit_t.append((time.perf_counter()-t)*1e3)
        t = time.perf_counter(); verify(rec.mldsa_alg, rec.signing_bytes(), sig, ident.public_key); log.prove_and_verify_inclusion(entry); verify_t.append((time.perf_counter()-t)*1e3)
        t = time.perf_counter(); dev.call_service(intent.command); act_t.append((time.perf_counter()-t)*1e3)
    ident.close()
    comp = {"guard_opa_ms": stats.mean(guard_t), "sign_ms": stats.mean(sign_t),
            "commit_ms": stats.mean(commit_t), "verify_ms": stats.mean(verify_t),
            "actuate_ms": stats.mean(act_t)}
    comp["total_ms"] = sum(comp.values())
    comp["total_no_opa_ms"] = comp["total_ms"] - comp["guard_opa_ms"]
    return comp


def main():
    print("liboqs", oqs.oqs_version(), "| benchmarking on M4 hub (feasibility only)...")
    mldsa = bench_mldsa()
    logr = bench_log()
    e2e = bench_end_to_end()

    lines = []
    lines.append("# Task 5 latency results — feasibility on a capable hub (Apple M4)\n")
    lines.append("> dec_01KVWZV01Z23GWW41451NH96X6: M4-only, **emulated** Home Assistant actuation. "
                 "These numbers show feasibility on a capable hub; they are **not** representative of a "
                 "constrained home device, and no physical actuation occurs.\n")
    lines.append(f"liboqs {oqs.oqs_version()}; ML-DSA via FIPS-204 params; means over 300 iters "
                 "(end-to-end over 50).\n")
    lines.append("## ML-DSA sign/verify (the PQC provenance primitive)\n")
    lines.append("| Param set | pk (B) | sig (B) | sign mean (ms) | sign median (ms) | verify mean (ms) | verify median (ms) |")
    lines.append("|-----------|-------:|--------:|---------------:|-----------------:|-----------------:|-------------------:|")
    for r in mldsa:
        lines.append(f"| {r['alg']} | {r['pk']} | {r['sig']} | {r['sign_ms']:.3f} | {r['sign_med']:.3f} "
                     f"| {r['verify_ms']:.3f} | {r['verify_med']:.3f} |")
    lines.append("")
    lines.append("## Tamper-evident log\n")
    lines.append(f"Merkle commit + inclusion-proof verify (ML-DSA-65 leaf): "
                 f"mean {logr['commit_incl_ms']:.3f} ms, median {logr['commit_incl_med']:.3f} ms.\n")
    lines.append("## End-to-end provenance -> emulated actuation (ML-DSA-65), by stage\n")
    lines.append("| Stage | mean (ms) |")
    lines.append("|-------|----------:|")
    lines.append(f"| OPA/Rego guard (subprocess) | {e2e['guard_opa_ms']:.3f} |")
    lines.append(f"| ML-DSA sign | {e2e['sign_ms']:.3f} |")
    lines.append(f"| Merkle commit | {e2e['commit_ms']:.3f} |")
    lines.append(f"| verify (sig + inclusion) | {e2e['verify_ms']:.3f} |")
    lines.append(f"| emulated actuation | {e2e['actuate_ms']:.3f} |")
    lines.append(f"| **total** | **{e2e['total_ms']:.3f}** |")
    lines.append(f"| total excl. OPA cold-start subprocess | {e2e['total_no_opa_ms']:.3f} |")
    lines.append("")
    lines.append("**Note:** the OPA guard latency is dominated by per-call CLI process start-up; a "
                 "long-running OPA server (or the Go/Rust OPA SDK) removes it. The crypto+log+verify "
                 "core is well under a typical smart-home actuation responsiveness budget on this hub.\n")

    out = os.path.join(HERE, "results.md")
    with open(out, "w") as f:
        f.write("\n".join(lines))
    print("\n".join(lines))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
