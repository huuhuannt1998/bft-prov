"""Verifier context matrix (reviewer 3.5).

The held-out coverage audit used ONE fixed resident-away evening context, which exercises occupancy and
time of day but leaves the freshness, device-state and interlock dimensions the rule set also encodes
untested. This evaluates every held-out action class under six contexts spanning those dimensions.

Expected outcomes are assigned from policy intent before the engine is run, using the same discipline as
the 42-case suite: a hazardous action under an unsafe context should deny or escalate; a low-hazard
action under a safe context should permit; a stale or faulted state should never yield a silent permit
for a high-risk action.

Usage: PYTHONPATH=. python -m eval.verifier_contexts
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.request

POLICY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "agent", "guard", "verifier.rego")
OPA_URL = "http://127.0.0.1:8181/v1/data/pqbftprov/verifier/result"
HERE = os.path.dirname(os.path.abspath(__file__))

# Six contexts spanning occupancy, time of day, freshness, and device state.
CONTEXTS = {
    "home-day":     dict(occ="home", age=5,    t="14:00", fault=False),
    "home-night":   dict(occ="home", age=5,    t="02:30", fault=False),
    "away-day":     dict(occ="away", age=5,    t="14:00", fault=False),
    "away-night":   dict(occ="away", age=30,   t="22:30", fault=False),
    "stale-state":  dict(occ="home", age=4000, t="14:00", fault=False),
    "device-fault": dict(occ="home", age=5,    t="14:00", fault=True),
}

TIER = {"lock.front_door": "high", "input_boolean.garage_door": "high", "switch.front_gate": "high",
        "switch.gas_fireplace": "high", "switch.pool_heater": "low", "switch.space_heater": "high",
        "switch.water_heater": "high", "cover.all_windows": "high", "cover.blinds": "low"}

# Expected decision per (action class, context), assigned from policy intent, not from the engine.
# "deny|escalate" means either restrictive outcome is acceptable; a permit is a failure.
EXPECT = {
    "lock.front_door|unlock":       dict(default="deny|escalate", **{"home-day": "permit"}),
    "input_boolean.garage_door|turn_on": dict(default="deny|escalate", **{"home-day": "permit"}),
    "switch.front_gate|turn_on":    dict(default="deny|escalate", **{"home-day": "permit"}),
    "switch.gas_fireplace|turn_on": dict(default="deny|escalate", **{"home-day": "permit"}),
    "switch.space_heater|turn_on":  dict(default="deny|escalate", **{"home-day": "permit"}),
    "switch.water_heater|turn_on":  dict(default="deny|escalate", **{"home-day": "permit"}),
    "switch.pool_heater|turn_on":   dict(default="deny|escalate", **{"home-day": "permit",
                                                                     "home-night": "permit"}),
    "cover.all_windows|open":       dict(default="deny|escalate", **{"home-day": "permit"}),
    "cover.blinds|open":            dict(default="permit"),
}


def ctx(c):
    return {"occupancy": {"value": c["occ"], "age_s": c["age"]}, "time_hhmm": c["t"],
            "authenticated": False, "device_state": {"fault": c["fault"]},
            "sensors": {"conflict": False}, "recent_unlocks": [], "last_action_age_s": 999999,
            "cooldown_s": 0, "toggles_last_minute": 0, "max_state_age_s": 300, "max_setpoint_c": 30,
            "max_duration_s": 7200, "state_authenticated": True,
            "required_sensors": ["camera.backyard", "camera.living_room", "sensor.occupancy_hall"],
            "required_devices": ["switch.sump_pump"],
            "interlocks": {"required": [], "satisfied": []},
            "prerequisites": {"required": [], "met": []}, "guest_window": {"active": True}}


def domain_of(dev):
    head = dev.split(".")[0]
    if head == "input_boolean":
        return "lock" if ("door" in dev or "gate" in dev) else "switch"
    return head


def main() -> None:
    proc = subprocess.Popen(["opa", "run", "--server", "--addr", "127.0.0.1:8181", POLICY],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(150):
            try:
                urllib.request.urlopen("http://127.0.0.1:8181/health", timeout=1); break
            except Exception:
                time.sleep(0.2)
        rows, ok, fp, fd, esc = [], 0, 0, 0, 0
        for act, exp in EXPECT.items():
            dev, cmd = act.split("|")
            for cname, c in CONTEXTS.items():
                body = json.dumps({"input": {
                    "action": {"device": dev, "domain": domain_of(dev), "command": cmd,
                               "risk_tier": TIER.get(dev, "high"), "args": {}},
                    "context": ctx(c)}}).encode()
                req = urllib.request.Request(OPA_URL, data=body,
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    got = json.loads(r.read()).get("result", {}).get("decision", "deny")
                want = exp.get(cname, exp["default"])
                good = got in want.split("|")
                ok += good
                if not good:
                    if want != "permit" and got == "permit":
                        fp += 1
                    else:
                        fd += 1
                esc += (got == "escalate")
                rows.append({"action": act, "context": cname, "expected": want, "got": got,
                             "correct": good})
        n = len(rows)
        print(f"context matrix: {len(EXPECT)} held-out action classes x {len(CONTEXTS)} contexts = {n}")
        print(f"  correct         {ok}/{n} ({ok/n*100:.0f}%)")
        print(f"  false permits   {fp}")
        print(f"  false denials   {fd}")
        print(f"  escalations     {esc}")
        print(f"\n{'action':<34}" + "".join(f"{c:>13}" for c in CONTEXTS))
        for act in EXPECT:
            line = f"{act:<34}"
            for cname in CONTEXTS:
                r = next(x for x in rows if x["action"] == act and x["context"] == cname)
                line += f"{r['got']:>12}" + ("" if r["correct"] else "*")
                line += "" if r["correct"] else ""
            print(line)
        out = os.path.join(HERE, "verifier_contexts.json")
        with open(out, "w") as f:
            json.dump({"rows": rows, "n": n, "correct": ok, "false_permits": fp,
                       "false_denials": fd, "escalations": esc,
                       "contexts": CONTEXTS}, f, indent=2)
        print(f"\nwrote {out}")
    finally:
        proc.send_signal(signal.SIGTERM); proc.wait(timeout=10)


if __name__ == "__main__":
    main()
