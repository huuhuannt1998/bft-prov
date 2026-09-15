"""
ML-DSA (FIPS 204) signing wrapper over liboqs/oqs — the post-quantum provenance primitive.

Per the Task-3 BUFF memo (docs/03-buff-memo): ML-DSA provides exclusive ownership + message-bound
signatures (tr=H(pk)/SHAKE-256), and we ADDITIONALLY bind pk + a domain/context tag into the signed
record at the application layer (see provenance/gateway/record.py). Primitive security is ASSUMED
from the verified liboqs implementation; not re-proven here.
"""
from __future__ import annotations
import oqs

# ML-DSA parameter sets exposed by liboqs (FIPS 204).
PARAMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DOMAIN = b"PQ-BFT-Prov/smart-home-actuation/v1"   # FIPS-204-style context/domain separator


class MLDSAIdentity:
    """An agent's ML-DSA keypair. The secret key lives inside the oqs.Signature object."""

    def __init__(self, alg: str = "ML-DSA-65"):
        if alg not in PARAMS:
            raise ValueError(f"unknown ML-DSA parameter set: {alg}")
        self.alg = alg
        self._signer = oqs.Signature(alg)
        self.public_key: bytes = self._signer.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    def close(self) -> None:
        self._signer.free()

    def __enter__(self): return self
    def __exit__(self, *exc): self.close()


def verify(alg: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Stateless verification against a given public key (the credited key)."""
    with oqs.Signature(alg) as v:
        return bool(v.verify(message, signature, public_key))


if __name__ == "__main__":
    for p in PARAMS:
        with MLDSAIdentity(p) as idA:
            msg = DOMAIN + b"|actuate:unlock_front_door"
            sig = idA.sign(msg)
            ok = verify(p, msg, sig, idA.public_key)
            print(f"{p}: pk={len(idA.public_key)}B sig={len(sig)}B verify={ok}")
