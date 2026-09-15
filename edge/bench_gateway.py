"""Constrained-gateway benchmark: the enforcement path only, portable to ARM.

Runs the SAME code the M4 evaluation runs (consensus.cert_schema, pymerkle, OPA) so the two platforms
are compared under one harness rather than two. Model inference is deliberately absent: a Raspberry Pi 3
has 1 GB of RAM and cannot host the agents, and in the deployed architecture it should not, since the
agents are a model service and the Pi is the enforcing gateway.

Measures, per platform:
  * ML-DSA sign / verify by parameter set
  * complete certificate verification at q = 1,2,3,5,7 (all signatures + coverage predicate)
  * certificate serialize / parse
  * Merkle append, inclusion-proof generation and verification
  * deterministic-verifier latency against a resident OPA server (skipped if opa is absent)
  * the full gateway path a committed actuation pays
  * platform identity, CPU count, RAM, and process RSS

Usage: PYTHONPATH=. python3 -m edge.bench_gateway --out edge/results_<host>.json
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import statistics as st
import subprocess
import time
import urllib.request

from pymerkle import InmemoryTree, verify_inclusion

from consensus.cert_schema import (CERT_VERSION, ActionRecord, Certificate, Enrollment, QuorumPolicy,
                                   Registry, canon, cast_vote, check_certificate, coverage_evidence, h)
from provenance.crypto.mldsa import MLDSAIdentity

SCHEMES = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SIGNERS = [1, 2, 3, 5, 7]
FAMILIES = ["llama", "qwen", "mistral", "gemma", "phi", "granite", "llama"]
DEFENSES = ["hierarchy", "struq", "provenance", "spotlight", "known_answer", "hierarchy", "struq"]
OPA_URL = "http://127.0.0.1:8181/v1/data/pqbftprov/verifier/result"
POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "agent", "guard", "verifier.rego")


def platform_info() -> dict:
    info = {"node": platform.node(), "system": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(), "processor": platform.processor()}
    try:
        info["cpu_count"] = os.cpu_count()
    except Exception:
        pass
    # CPU model and RAM, portable across macOS and Linux
    try:
        if platform.system() == "Darwin":
            info["cpu_model"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                               capture_output=True, text=True).stdout.strip()
            info["ram_bytes"] = int(subprocess.run(["sysctl", "-n", "hw.memsize"],
                                                   capture_output=True, text=True).stdout.strip())
        else:
            for line in open("/proc/cpuinfo"):
                if line.startswith(("model name", "Model")):
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
            for line in open("/proc/meminfo"):
                if line.startswith("MemTotal"):
                    info["ram_bytes"] = int(line.split()[1]) * 1024
                    break
            if os.path.exists("/proc/device-tree/model"):
                info["board"] = open("/proc/device-tree/model").read().strip("\x00")
            # An under-powered Pi silently throttles, which would corrupt every timing below. Record
            # the firmware throttle word so a degraded run is visible instead of being reported as a
            # constrained-device result. Bit 0 = under-voltage now, bit 16 = under-voltage since boot,
            # bit 2 = currently throttled, bit 18 = throttled since boot.
            for vc in ("/usr/bin/vcgencmd", "/opt/vc/bin/vcgencmd"):
                if os.path.exists(vc):
                    out = subprocess.run([vc, "get_throttled"], capture_output=True, text=True).stdout
                    word = out.strip().split("=")[-1]
                    info["throttled_raw"] = word
                    try:
                        w = int(word, 16)
                        info["undervoltage_now"] = bool(w & 0x1)
                        info["undervoltage_since_boot"] = bool(w & 0x10000)
                        info["throttled_now"] = bool(w & 0x4)
                        info["throttled_since_boot"] = bool(w & 0x40000)
                        info["measurement_valid"] = not (w & 0x50005)
                    except ValueError:
                        pass
                    break
    except Exception as e:
        info["probe_error"] = repr(e)
    return info


def rss_bytes() -> int:
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())],
                                 capture_output=True, text=True).stdout.strip()
            return int(out) * 1024
        for line in open(f"/proc/{os.getpid()}/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1]) * 1024
    except Exception:
        pass
    return -1


def make_action(seq: int) -> ActionRecord:
    return ActionRecord(
        action_id=f"act-{seq:06d}", device_id="lock.front_door", action="unlock",
        args={"duration_s": 30}, risk_tier="high",
        request_commitment=h(b"let the cleaner in at 10am"),
        context_commitment=h(b"<calendar entry with injected instruction>"),
        system_prompt_commitment=h(b"<system prompt v3>"), policy_commitment=h(b"<rego bundle v7>"),
        epoch=4, view=11, nonce=f"nonce-{seq:012d}", sequence=seq,
        timestamp="2026-08-01T12:00:00Z", prev_checkpoint=h(b"<sth-1042>"))


def build(scheme: str, q: int):
    reg, ids = Registry(), []
    for i in range(q):
        idn = MLDSAIdentity(scheme)
        kid = f"key-{i:02d}"
        reg.enroll(Enrollment(kid, idn.public_key.hex(), scheme, f"model-{i}", h(f"w{i}".encode()),
                              "q4_K_M", "ollama-0.6.2", DEFENSES[i % len(DEFENSES)],
                              FAMILIES[i % len(FAMILIES)], f"proc-{i}", 0))
        ids.append((kid, idn))
    return reg, ids


def bench_primitive(iters: int) -> list[dict]:
    rows = []
    msg = b"gateway-primitive-benchmark"
    for s in SCHEMES:
        idn = MLDSAIdentity(s)
        sig = idn.sign(msg)
        ts, tv = [], []
        for _ in range(iters):
            t0 = time.perf_counter(); idn.sign(msg); ts.append(time.perf_counter() - t0)
        from provenance.crypto.mldsa import verify as mv
        for _ in range(iters):
            t0 = time.perf_counter(); mv(s, msg, sig, idn.public_key); tv.append(time.perf_counter() - t0)
        rows.append({"scheme": s, "pk_bytes": len(idn.public_key), "sig_bytes": len(sig),
                     "sign_ms": round(st.mean(ts) * 1000, 4), "verify_ms": round(st.mean(tv) * 1000, 4)})
        idn.close()
    return rows


def bench_certificate(iters: int) -> list[dict]:
    rows = []
    for scheme in SCHEMES:
        for q in SIGNERS:
            reg, ids = build(scheme, q)
            policy = QuorumPolicy("q-of-N+coverage", q,
                                  {"family": min(3, q)} if q >= 3 else {},
                                  {"family": max(1, q // 2)} if q >= 3 else {})
            t_sign, t_ser, t_parse, t_ver, t_app, t_pf, t_pv = ([] for _ in range(7))
            cert_bytes = proof_bytes = 0
            for it in range(iters):
                a = make_action(it + 1)
                per = []
                votes = []
                for kid, idn in ids:
                    t0 = time.perf_counter(); v = cast_vote(kid, idn, a, "approve")
                    per.append(time.perf_counter() - t0); votes.append(v)
                t_sign.append(per)
                cert = Certificate(CERT_VERSION, a, votes, policy.policy_id)
                cert.coverage_evidence = coverage_evidence(cert, reg)
                t0 = time.perf_counter(); blob = cert.to_bytes(); t_ser.append(time.perf_counter() - t0)
                t0 = time.perf_counter(); back = Certificate.from_bytes(blob)
                t_parse.append(time.perf_counter() - t0)
                t0 = time.perf_counter(); ok, why = check_certificate(back, reg, policy, 4)
                t_ver.append(time.perf_counter() - t0)
                assert ok, why
                tree = InmemoryTree(algorithm="sha256")
                t0 = time.perf_counter(); idx = tree.append_entry(blob)
                t_app.append(time.perf_counter() - t0)
                t0 = time.perf_counter(); pf = tree.prove_inclusion(idx)
                t_pf.append(time.perf_counter() - t0)
                t0 = time.perf_counter()
                verify_inclusion(tree.get_leaf(idx), tree.get_state(), pf)
                t_pv.append(time.perf_counter() - t0)
                cert_bytes = len(blob)
                proof_bytes = len(canon([str(p) for p in pf.path]))
            for _, idn in ids:
                idn.close()
            ms = lambda xs: round(st.mean(xs) * 1000, 4)
            gw = st.mean(t_parse) + st.mean(t_ver) + st.mean(t_app) + st.mean(t_pf)
            rows.append({
                "scheme": scheme, "signers": q, "cert_bytes": cert_bytes,
                "inclusion_proof_bytes": proof_bytes,
                "registry_bytes_one_off": Registry.bytes_size(build(scheme, q)[0]),
                "sign_ms_per_signer": ms([x for xs in t_sign for x in xs]),
                "sign_ms_total_cpu": ms([sum(x) for x in t_sign]),
                "sign_ms_wallclock_parallel": ms([max(x) for x in t_sign]),
                "serialize_ms": ms(t_ser), "parse_ms": ms(t_parse),
                "verify_all_sigs_ms": ms(t_ver), "merkle_append_ms": ms(t_app),
                "proof_gen_ms": ms(t_pf), "proof_verify_ms": ms(t_pv),
                "gateway_path_ms": round(gw * 1000, 4),
                "authorization_ms_parallel_signing": round((st.mean([max(x) for x in t_sign]) + gw) * 1000, 4),
            })
    return rows


def bench_policy(iters: int) -> dict:
    if not shutil.which("opa"):
        return {"available": False, "reason": "opa not installed"}
    proc = subprocess.Popen(["opa", "run", "--server", "--addr", "127.0.0.1:8181", POLICY],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(150):
            try:
                urllib.request.urlopen("http://127.0.0.1:8181/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            return {"available": False, "reason": "opa server did not start"}
        payload = json.dumps({"input": {
            "action": {"device": "lock.front_door", "domain": "lock", "command": "unlock",
                       "risk_tier": "high", "args": {}},
            "context": {"occupancy": {"value": "home", "age_s": 5}, "time_hhmm": "14:00",
                        "authenticated": True, "recent_unlocks": [], "max_state_age_s": 300}}}).encode()
        t = []
        for _ in range(iters):
            req = urllib.request.Request(OPA_URL, data=payload,
                                         headers={"Content-Type": "application/json"})
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            t.append((time.perf_counter() - t0) * 1000)
        t.sort()
        return {"available": True, "mean_ms": round(st.mean(t), 4), "p50_ms": round(t[len(t) // 2], 4),
                "p95_ms": round(t[int(0.95 * len(t))], 4), "throughput_per_s": round(1000 / st.mean(t))}
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=20)
    ap.add_argument("--policy-iters", type=int, default=200)
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    info = platform_info()
    print(f"platform: {info.get('board') or info.get('cpu_model','?')} | "
          f"{info['machine']} | {info.get('cpu_count','?')} cores | "
          f"{round(info.get('ram_bytes',0)/1e9,2)} GB")
    if info.get("measurement_valid") is False:
        print("  !! UNDER-VOLTAGE OR THROTTLING DETECTED -- timings from this run are NOT valid as a\n"
              "     constrained-device measurement. Use a supply rated 2.5 A and re-run.")

    t0 = time.perf_counter()
    prim = bench_primitive(a.iters)
    cert = bench_certificate(a.iters)
    pol = bench_policy(a.policy_iters)
    elapsed = time.perf_counter() - t0

    print(f"\n{'scheme':<11}{'sign':>8}{'verify':>8}  (ms, single signature)")
    for r in prim:
        print(f"{r['scheme']:<11}{r['sign_ms']:>8.3f}{r['verify_ms']:>8.3f}")
    print(f"\n{'scheme':<11}{'q':>2}{'cert B':>9}{'verify':>9}{'gw path':>9}{'total':>9}  (ms)")
    for r in cert:
        if r["scheme"] == "ML-DSA-65":
            print(f"{r['scheme']:<11}{r['signers']:>2}{r['cert_bytes']:>9}"
                  f"{r['verify_all_sigs_ms']:>9.3f}{r['gateway_path_ms']:>9.3f}"
                  f"{r['authorization_ms_parallel_signing']:>9.3f}")
    print(f"\npolicy: {pol}")
    print(f"rss: {rss_bytes()/1e6:.1f} MB | benchmark wall time {elapsed:.1f}s")

    out = a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                f"results_{info['node'].split('.')[0]}.json")
    with open(out, "w") as f:
        json.dump({"platform": info, "primitive": prim, "certificate": cert, "policy": pol,
                   "rss_bytes": rss_bytes(), "iters": a.iters, "wall_time_s": round(elapsed, 1)},
                  f, indent=2)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
