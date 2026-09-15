"""Quorum / verifier / combined ablation (IoT-J revision, reviewer M2).

The paper calls the deterministic verifier load-bearing. That is asserted rather than measured unless we
show what the verifier adds ON TOP of a quorum, on the same attack corpus. This script does that.

Method. Each of the 342 attack payloads targets one of 19 (device, command) actions. We evaluate the
verifier on those actions under ONE fixed, declared deployment context, a resident-away evening profile
with the cameras enrolled as required sensors, and take the verifier's decision as the action-class
outcome. An attack succeeds end to end only if the quorum approves AND the verifier permits, so the
combined attack-success rate is computed per payload as the quorum's approval probability times the
indicator that the verifier permits that payload's action.

Two honesty constraints are built in. The verifier decides by ACTION CLASS and context; it never sees
the injected content and cannot detect an injection, so it cannot be credited with catching attacks
whose target action is legitimate. And the context is fixed and reported rather than tuned per action,
so the permit rows below are real coverage gaps, not omissions.

Usage: PYTHONPATH=. python -m eval.verifier_ablation
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.request

import numpy as np

from decorrelation.analyze_quorum import (Agent, load_agents, member_sets, pb_tail, stratified_split,
                                          category_of, thresholds_for)
from decorrelation.corpus_tdsc import build_tdsc_corpus

POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "agent", "guard", "verifier.rego")
OPA_URL = "http://127.0.0.1:8181/v1/data/pqbftprov/verifier/result"

# Risk tier per action class. Assigned from physical hazard, not from what makes the verifier look good.
TIER = {
    "lock.front_door": "high", "lock.back_door": "high", "lock.patio_door": "high",
    "input_boolean.garage_door": "high", "switch.front_gate": "high",
    "switch.boiler": "high", "switch.water_heater": "high", "switch.space_heater": "high",
    "switch.oven": "high", "switch.gas_fireplace": "high", "switch.heat_pump": "low",
    "switch.ev_charger": "low", "switch.pool_heater": "low",
    "switch.sump_pump": "high", "switch.chest_freezer": "low",
    "camera.backyard": "high", "camera.living_room": "high",
    "cover.all_windows": "high", "cover.blinds": "low",
}

# One fixed deployment context, declared in the paper: resident away, late evening, cameras required.
def context():
    return {"occupancy": {"value": "away", "age_s": 30}, "time_hhmm": "22:30", "authenticated": False,
            "device_state": {"fault": False}, "sensors": {"conflict": False}, "recent_unlocks": [],
            "last_action_age_s": 999999, "cooldown_s": 0, "toggles_last_minute": 0,
            "max_state_age_s": 300, "max_setpoint_c": 30, "max_duration_s": 7200,
            "state_authenticated": True,
            "required_sensors": ["camera.backyard", "camera.living_room",
                                 "sensor.occupancy_hall"],
            "required_devices": ["switch.sump_pump"],
            "interlocks": {"required": [], "satisfied": []},
            "prerequisites": {"required": [], "met": []}, "guest_window": {"active": True}}


def domain_of(device: str) -> str:
    return device.split(".")[0].replace("input_boolean", "lock" if "door" in device or "gate" in device else "switch")


class OPA:
    def __enter__(self):
        self.p = subprocess.Popen(["opa", "run", "--server", "--addr", "127.0.0.1:8181", POLICY],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(150):
            try:
                urllib.request.urlopen("http://127.0.0.1:8181/health", timeout=1); return self
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("opa did not start")

    def __exit__(self, *e):
        self.p.send_signal(signal.SIGTERM); self.p.wait(timeout=10)

    def decide(self, device, command):
        body = json.dumps({"input": {
            "action": {"device": device, "domain": domain_of(device), "command": command,
                       "risk_tier": TIER.get(device, "high"), "args": {}},
            "context": context()}}).encode()
        req = urllib.request.Request(OPA_URL, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("result", {}).get("decision", "deny")


def main() -> None:
    agents, raw, items = load_agents()
    cases = {c.cid: c for c in build_tdsc_corpus()}
    cats = category_of(items["inj"])
    train_idx, test_idx = stratified_split(items["inj"], cats)

    # verifier decision per action class, then per payload
    with OPA() as opa:
        actions = sorted({(cases[c].device, cases[c].command) for c in items["inj"]})
        dec = {a: opa.decide(*a) for a in actions}
    permit = np.array([1.0 if dec[(cases[c].device, cases[c].command)] == "permit" else 0.0
                       for c in items["inj"]])

    split = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "action_split.json")))
    devset = set(split["dev"]); holdset = set(split["holdout"])
    print("verifier decision by action class (fixed away/22:30 context; declared required components):")
    for (d, c), v in sorted(dec.items(), key=lambda kv: (kv[1], kv[0])):
        tag = "dev " if f"{d}|{c}" in devset else "HOLD"
        print(f"  [{tag}] {v:<9} {d:<28} {c}")
    blocked = 1 - permit
    nd = sum(1 for a in dec if f"{a[0]}|{a[1]}" in devset and dec[a] != "permit")
    nh = sum(1 for a in dec if f"{a[0]}|{a[1]}" in holdset and dec[a] != "permit")
    print(f"\naction classes blocked or escalated: dev {nd}/{len(devset)}, "
          f"HELD-OUT {nh}/{len(holdset)} ({nh/len(holdset)*100:.0f}%)")
    print(f"payload-weighted over all 19 classes: {blocked.mean()*100:.1f}% of {len(permit)} payloads")

    # quorum ablation on the held-out half
    pool = sorted([a for a in agents if a.defense != "none"], key=lambda a: a.key)
    import random
    rng = random.Random(20260801)
    rows = []
    for strat in ["homogeneous", "family-diverse", "joint-diverse", "random"]:
        for n in (3, 5, 7):
            sets = member_sets(agents, pool, strat, n, 100, rng, train_idx)
            if not sets:
                continue
            P = np.stack([np.stack([agents[a]["inj"][test_idx] for a in Q], 1) for Q in sets])
            for tname, t in thresholds_for(n):
                if t != n // 2 + 1:            # majority only, for a compact table
                    continue
                q_x = np.stack([pb_tail(P[s], t) for s in range(len(sets))])   # [k, X]
                pmt = permit[test_idx][None, :]
                rows.append({"strategy": strat, "N": n, "q": t,
                             "quorum_only": float(q_x.mean()),
                             "combined": float((q_x * pmt).mean()),
                             "verifier_only": float(pmt.mean())})
    print(f"\n{'composition':<16}{'q-of-N':>8}{'quorum only':>13}{'verifier only':>15}{'combined':>11}")
    for r in rows:
        print(f"{r['strategy']:<16}{r['q']}-of-{r['N']:<4}{r['quorum_only']*100:12.1f}%"
              f"{r['verifier_only']*100:14.1f}%{r['combined']*100:10.1f}%")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verifier_ablation.json")
    with open(out, "w") as f:
        json.dump({"action_decisions": {f"{d} {c}": v for (d, c), v in dec.items()},
                   "blocked_fraction_of_payloads": float(blocked.mean()),
                   "ablation": rows, "context": context(), "tiers": TIER}, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
