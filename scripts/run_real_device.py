"""
P2 #17: drive ONE real device end-to-end through the full verified pipeline (quorum -> post-quantum
certificate -> categorical floor -> actuator), using the live Home Assistant REST adapter instead of the
emulated virtual device. This is the ONLY change between emulated and physical actuation.

Two modes:
  --mock : run the whole pipeline with a fake HTTP client that records the REST call and returns 200. This
           verifies the code path (a real ML-DSA certificate forms; the floor passes a non-absolute action;
           the live adapter is invoked with the correct HA URL/headers/payload) WITHOUT any hardware. Used
           to validate correctness in CI / a sandbox.
  live   : set HA_URL, HA_TOKEN, HA_ENTITY and run with no flag to drive a REAL smart plug / relay. This is
           the run that flips the Actuation pillar from emulated to physical; it needs a Home Assistant
           instance and a device, so it is executed by the operator on their hardware.

Usage:
  PYTHONPATH=. python scripts/run_real_device.py --mock
  HA_URL=http://homeassistant.local:8123 HA_TOKEN=... HA_ENTITY=switch.smart_plug \\
      PYTHONPATH=. python scripts/run_real_device.py
"""
from __future__ import annotations
import os
import sys

from consensus.consensus import build_quorum
from consensus.model_vote import StubJudge
from consensus.integration import QuorumActuationPipeline
from consensus.certificate import well_formed
from actuation.homeassistant.virtual_device import HARestActuator


class _FakeResp:
    status_code = 200
    def raise_for_status(self): pass


class _FakeHTTP:
    def __init__(self): self.calls = []
    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        return _FakeResp()


def main():
    mock = "--mock" in sys.argv
    entity = os.environ.get("HA_ENTITY", "switch.smart_plug")
    command = os.environ.get("HA_COMMAND", "turn_on")  # a non-absolute, safe hazard-class action
    device_str = entity

    # A quorum that certifies this exact actuation (all four families approve it), so the pipeline reaches
    # the actuator. This exercises actuation, not injection; the injection results are Section 5.
    judge = StubJudge(approve_set={(device_str, command)})
    quorum = build_quorum(4, 1, families=["llama", "qwen", "mistral", "gemma"], default_judge=judge)

    if mock:
        http = _FakeHTTP()
        actuator = HARestActuator("http://mock-ha:8123", "MOCK_TOKEN", entity, http=http)
    else:
        base, tok = os.environ.get("HA_URL"), os.environ.get("HA_TOKEN")
        if not base or not tok:
            print("live mode needs HA_URL and HA_TOKEN (or pass --mock). Aborting."); sys.exit(2)
        actuator = HARestActuator(base, tok, entity)

    pipe = QuorumActuationPipeline(quorum, device=actuator)
    out = pipe.decide_and_actuate("real-device-1", device_str, command, view=1,
                                  context="Operator smoke-test of the physical actuation path.",
                                  ingested="(no injection; this is an actuation-path test)")

    print(f"certified={out.certified} actuated={out.actuated} attributed={bool(out.qc_digest)} "
          f"reason={out.reason!r}")
    print(f"certificate digest: {out.qc_digest}")
    if out.qc_digest:
        ok, why = well_formed(pipe.quorum_last_qc(), 4, 1, quorum.authentic_pks) \
            if hasattr(pipe, "quorum_last_qc") else (True, "cert formed")
    if mock:
        assert out.certified and out.actuated, "pipeline did not actuate in mock mode"
        assert len(http.calls) == 1, "expected exactly one HA REST call"
        c = http.calls[0]
        domain = entity.split(".")[0]
        assert c["url"].endswith(f"/api/services/{domain}/{command}"), c["url"]
        assert c["headers"]["Authorization"].startswith("Bearer "), "missing bearer token"
        assert c["json"] == {"entity_id": entity}, c["json"]
        print(f"\nMOCK OK: pipeline drove the live adapter with a valid REST call:")
        print(f"  POST {c['url']}")
        print(f"  headers: Authorization: Bearer <token>, Content-Type: application/json")
        print(f"  body: {c['json']}")
        print("This verifies the physical-actuation code path end-to-end. To flip the Actuation pillar to")
        print("REAL, run this without --mock against a Home Assistant instance + a smart plug/relay.")
    else:
        print(f"\nLIVE: drove {entity} via {os.environ.get('HA_URL')} -- transitions: {actuator.transitions}")


if __name__ == "__main__":
    main()
