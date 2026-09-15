"""Per-signer signing service: one OS process per signer, one key file per process.

Review section 15. The earlier prototype held distinct logical signing keys inside ONE process, so a
reviewer could correctly object that a single compromised process reaches every key and the "distinct
signers" in a certificate are a bookkeeping convention rather than a boundary.

This narrows that gap without hardware. Each signer runs as its own process with its own key file, and
the file is created 0600 and owned by the launching identity. A signer answers only for its own key ID,
holds no other signer's material, and never returns a private key over the socket. The gateway talks to
each signer over a per-signer UNIX domain socket, so there is no shared writable key directory and no
network surface.

What this establishes: per-signer OS process separation on a single host, so compromising one model
process yields one signing key rather than all of them. What it does NOT establish: machine
independence, or resistance to root or kernel compromise, which reaches every key on the host and stays
outside the defended boundary.

Usage: python -m consensus.signerd.signer_service --key-id S1 --socket /tmp/s1.sock --key-dir ...
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import stat
import sys

try:
    import oqs
except Exception:                                            # pragma: no cover
    oqs = None

ALG = "ML-DSA-65"


class SignerState:
    """Owns exactly one secret key, loaded once, never emitted."""

    def __init__(self, key_id: str, key_dir: str, alg: str = ALG):
        self.key_id, self.alg = key_id, alg
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(key_dir, f"{key_id}.sk")
        if os.path.exists(self.path):
            self._require_private(self.path)
            with open(self.path, "rb") as f:
                self.sk = f.read()
            self.signer = oqs.Signature(alg, self.sk)
            self.pk = self.signer.generate_keypair() if False else None
        else:
            self.signer = oqs.Signature(alg)
            self.pk = self.signer.generate_keypair()
            self.sk = self.signer.export_secret_key()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.sk)
        pkp = os.path.join(key_dir, f"{key_id}.pk")
        if self.pk is not None:
            with open(pkp, "wb") as f:
                f.write(self.pk)
        elif os.path.exists(pkp):
            with open(pkp, "rb") as f:
                self.pk = f.read()

    @staticmethod
    def _require_private(path: str) -> None:
        """Refuse to start on a key any other identity can read. Fail closed, loudly."""
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError(f"{path} is group/world accessible; refusing to load")

    def sign(self, message: bytes) -> bytes:
        return self.signer.sign(message)


def make_handler(state: SignerState):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                req = json.loads(self.rfile.readline().decode())
            except Exception:
                self.wfile.write(b'{"error":"malformed request"}\n'); return
            op = req.get("op")
            if op == "pubkey":
                out = {"key_id": state.key_id, "alg": state.alg,
                       "pk": state.pk.hex() if state.pk else None}
            elif op == "sign":
                # a signer answers only for its own key id; a request naming another signer is refused
                if req.get("key_id") not in (None, state.key_id):
                    out = {"error": f"this process holds {state.key_id} only"}
                else:
                    msg = bytes.fromhex(req.get("message", ""))
                    out = {"key_id": state.key_id, "alg": state.alg,
                           "signature": state.sign(msg).hex()}
            else:
                out = {"error": f"unknown op {op!r}"}
            self.wfile.write((json.dumps(out) + "\n").encode())
    return Handler


class UDSServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--socket", required=True)
    ap.add_argument("--key-dir", required=True)
    a = ap.parse_args()
    if oqs is None:
        print("liboqs bindings unavailable", file=sys.stderr); sys.exit(2)
    state = SignerState(a.key_id, a.key_dir)
    if os.path.exists(a.socket):
        os.unlink(a.socket)
    srv = UDSServer(a.socket, make_handler(state))
    os.chmod(a.socket, 0o600)                                  # only the launching identity may connect
    print(f"signer {a.key_id} ready on {a.socket} (pid {os.getpid()})", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        if os.path.exists(a.socket):
            os.unlink(a.socket)


if __name__ == "__main__":
    main()
