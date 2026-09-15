#!/usr/bin/env bash
# PQ-BFT-Prov — single-host environment bring-up (Apple-Silicon macOS / M-series).
# M4-ONLY per dec_01KVWZV01Z23GWW41451NH96X6: everything runs on one MacBook M4,
# actuation is EMULATED via Home Assistant virtual devices (no GPIO / no physical device).
# Greenfield: nothing here reuses a prior project; only public tools/benchmarks.
set -euo pipefail

echo "[1/6] System toolchain via Homebrew"
brew install opa liboqs                      # OPA/Rego runtime guard; liboqs (ML-DSA/ML-KEM)
brew trust tamarin-prover/tap                # Homebrew >=6 refuses untrusted taps
brew install tamarin-prover/tap/tamarin-prover   # pulls maude; Tamarin 1.12.x
brew install opam                            # for ProVerif (secondary cross-check)

echo "[2/6] Python crypto + quantum-threat stack"
pip3 install qiskit qiskit-aer               # RQ1 Shor-forgery (Aer simulator ONLY — no real QPU)
pip3 install cryptography pycryptodome       # classical (RSA/ECDSA) baseline chain
pip3 install liboqs-python                   # `oqs` — auto-builds shared liboqs into ~/_oqs on first import

echo "[3/6] Agent + policy-guard stack (LLM is an UNTRUSTED oracle)"
pip3 install mcp smolagents                  # MCP SDK + lightweight agent framework (local-model capable)
# OPA installed above is the RUNTIME instantiation of the verified guard automaton.

echo "[4/6] Tamper-evident provenance log"
pip3 install pymerkle                        # Merkle log; signed with ML-DSA (not the conventional Ed25519)

echo "[5/6] Emulated smart-home actuation"
pip3 install homeassistant                   # virtual devices = the (emulated) actuation endpoint

echo "[6/6] Local LLM runtime + ProVerif"
# ollama already present; pull a small open model when needed for the Task-5 demonstrator:
#   ollama pull llama3.2:3b
opam init --no-setup --disable-sandboxing -y || true
eval "$(opam env)"
opam install -y proverif

echo "Done. See env/versions.lock for pinned versions and README.md for repo layout."
