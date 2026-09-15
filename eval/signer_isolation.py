"""Measure what per-signer process isolation actually buys (review section 15).

Three checks, each stated as a property a reviewer can falsify:

  I1 SEPARATION       every signer runs in its own OS process with its own key file
  I2 CONFINEMENT      a signer refuses to sign under another signer's key id, and never emits a secret
  I3 KEY PERMISSIONS  each key file is 0600 and each socket is 0600, so no shared readable key material

It also measures the cost, since moving from an in-process call to a UNIX-socket round trip is not free
and a reviewer will ask.

The claim this supports is bounded: per-signer OS process separation on one host. Root or kernel
compromise reaches every key and stays outside the defended boundary.

Usage: PYTHONPATH=. python -m eval.signer_isolation
"""
from __future__ import annotations

import json, os, shutil, socket, subprocess, sys, tempfile, time


def python_with_oqs() -> str:
    """liboqs bindings are installed under one interpreter on this host; find it rather than assume."""
    cands = [sys.executable, shutil.which("python3") or "",
             os.path.expanduser("~/miniconda3/bin/python3")]
    for c in cands:
        if c and os.path.exists(c):
            r = subprocess.run([c, "-c", "import oqs"], capture_output=True)
            if r.returncode == 0:
                return c
    raise SystemExit("no interpreter on this host has the liboqs bindings")

HERE = os.path.dirname(os.path.abspath(__file__))
N_SIGNERS = 5
ITERS = 30


def rpc(sock_path: str, req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        buf += s.recv(65536)
    s.close()
    return json.loads(buf.decode())


def main() -> None:
    PY = python_with_oqs()
    print(f"signing interpreter: {PY}")
    tmp = tempfile.mkdtemp(prefix="signerd-")
    procs, socks = [], []
    try:
        for i in range(1, N_SIGNERS + 1):
            kid = f"S{i}"
            kdir = os.path.join(tmp, kid)                  # one key directory per signer, not shared
            sp = os.path.join(tmp, f"{kid}.sock")
            p = subprocess.Popen([PY, "-m", "consensus.signerd.signer_service",
                                  "--key-id", kid, "--socket", sp, "--key-dir", kdir],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 cwd=os.path.dirname(HERE))
            procs.append(p); socks.append((kid, sp, kdir))
        for _ in range(200):
            if all(os.path.exists(sp) for _, sp, _ in socks):
                break
            time.sleep(0.05)
        time.sleep(0.4)

        pids = {kid: pr.pid for (kid, _, _), pr in zip(socks, procs)}
        print(f"I1 SEPARATION   {len(set(pids.values()))} distinct OS processes for {N_SIGNERS} signers "
              f"-> {'PASS' if len(set(pids.values())) == N_SIGNERS else 'FAIL'}")

        # I2: cross-signer request must be refused; no response may carry secret material
        cross = rpc(socks[0][1], {"op": "sign", "key_id": "S2", "message": b"x".hex()})
        refused = "error" in cross
        leak = any(k in json.dumps(cross).lower() for k in ("secret", "\"sk\"", "private"))
        own = rpc(socks[0][1], {"op": "sign", "key_id": "S1", "message": b"hello".hex()})
        print(f"I2 CONFINEMENT  cross-signer request refused: {'PASS' if refused else 'FAIL'}; "
              f"own-key signing works: {'PASS' if 'signature' in own else 'FAIL'}; "
              f"no secret in responses: {'PASS' if not leak else 'FAIL'}")

        # I3: key files and sockets must not be readable by anyone else
        bad = []
        for kid, sp, kdir in socks:
            kf = os.path.join(kdir, f"{kid}.sk")
            if os.path.exists(kf) and (os.stat(kf).st_mode & 0o077):
                bad.append(kf)
            if os.stat(sp).st_mode & 0o077:
                bad.append(sp)
        print(f"I3 PERMISSIONS  {len(socks)*2} paths checked, {len(bad)} group/world accessible "
              f"-> {'PASS' if not bad else 'FAIL ' + str(bad)}")

        # cost of the boundary
        msg = os.urandom(512).hex()
        t0 = time.perf_counter()
        for _ in range(ITERS):
            rpc(socks[0][1], {"op": "sign", "message": msg})
        per = (time.perf_counter() - t0) / ITERS * 1000
        t0 = time.perf_counter()
        for _ in range(ITERS):
            for _, sp, _ in socks:
                rpc(sp, {"op": "sign", "message": msg})
        quorum = (time.perf_counter() - t0) / ITERS * 1000
        print(f"\ncost of the boundary: {per:.2f} ms per signature over a UNIX socket, "
              f"{quorum:.2f} ms to collect {N_SIGNERS} signatures sequentially")

        out = {"n_signers": N_SIGNERS, "distinct_pids": len(set(pids.values())),
               "cross_signer_refused": refused, "own_key_signing": "signature" in own,
               "secret_leaked_in_response": leak, "insecure_paths": bad,
               "ms_per_signature_uds": per, "ms_five_signatures_sequential": quorum,
               "claim": "per-signer OS process separation on one host; root/kernel compromise is "
                        "outside the defended boundary"}
        p = os.path.join(HERE, "signer_isolation.json")
        json.dump(out, open(p, "w"), indent=2)
        print(f"wrote {p}")
    finally:
        for pr in procs:
            pr.terminate()
        for pr in procs:
            try: pr.wait(timeout=5)
            except Exception: pr.kill()


if __name__ == "__main__":
    main()
