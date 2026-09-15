"""
Policy guard: evaluates an actuation request against policy.rego via the OPA CLI.
The LLM agent cannot influence this — the decision is made outside the agent (P2 in the threat model).
"""
from __future__ import annotations
import json
import os
import subprocess

_POLICY = os.path.join(os.path.dirname(__file__), "policy.rego")


def evaluate(device: str, command: str, authorized: bool = False, context: dict | None = None) -> str:
    """Return "permit" or "deny" from the Rego guard automaton."""
    inp = json.dumps({"device": device, "command": command,
                       "authorized": authorized, "context": context or {}})
    proc = subprocess.run(
        ["opa", "eval", "-f", "raw", "-d", _POLICY, "-I", "data.pqbftprov.decision"],
        input=inp, capture_output=True, text=True, check=True,
    )
    out = proc.stdout.strip()
    return out if out in ("permit", "deny") else "deny"


if __name__ == "__main__":
    print("lights on        :", evaluate("light.kitchen", "turn_on"))
    print("door unlock (no)  :", evaluate("input_boolean.front_door", "turn_on"))
    print("door unlock (auth):", evaluate("input_boolean.front_door", "turn_on", authorized=True))
    print("boiler on (no)    :", evaluate("switch.boiler", "turn_on"))
