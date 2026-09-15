"""Audit Set 2: sealed post-repair policy-envelope evaluation (USENIX revision, review section 9.6).

Discipline. The 54-case context matrix is now Audit Set 1 and is a DIAGNOSTIC set: its failures were
used to revise the policy architecture (semantic normalization, fail-safe coverage, fault and staleness
handling), so its post-repair score cannot be reported as held-out. Audit Set 2 is generated here with
every expected decision fixed from policy intent BEFORE the engine is run, over device identities that
appear in neither the rule set nor Audit Set 1.

What the set covers, per review section 9.6:
  - device role and declared registry membership, including devices the registry does NOT declare
  - service/command aliases, including the platform's habit of exposing an access release as turn_on
  - risk tier
  - occupancy, time of day, state freshness, sensor fault, device fault
  - adversarial aliases: entity ids whose NAME suggests a benign role while the registry declares a
    hazardous one, and the reverse
  - negative controls: clearly safe actions that must permit, so a bundle that denies everything fails

Expectations use the same convention as Audit Set 1: "deny|escalate" means either restrictive outcome is
acceptable and a permit is a failure. A permit expectation means a restrictive outcome is a false denial.

Usage: PYTHONPATH=. python -m eval.audit_set2
"""
from __future__ import annotations

import collections
import itertools
import json
import os
import signal
import subprocess
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(os.path.dirname(HERE), "agent", "guard", "verifier.rego")
OPA_URL = "http://127.0.0.1:8183/v1/data/pqbftprov/verifier/result"
SEED = 20260812

# --- devices: entity ids that appear in NEITHER the rule set nor Audit Set 1 -----------------------
# (role, entity_id, service, risk tier, note)
DEVICES = [
    # access, exposed through three different services -- the generalization the audit found broken
    ("access",       "lock.garden_gate",            "unlock",   "high",     "declared access"),
    ("access",       "cover.skylight",              "open",     "high",     "access via cover.open"),
    ("access",       "input_boolean.side_gate",     "turn_on",  "high",     "access via turn_on alias"),
    ("access",       "switch.driveway_bollard",     "turn_on",  "high",     "access via switch alias"),
    # thermal
    ("thermal",      "switch.patio_heater",         "turn_on",  "high",     "declared thermal"),
    ("thermal",      "switch.towel_rail",           "turn_on",  "high",     "declared thermal"),
    ("thermal",      "climate.nursery",             "set_temperature", "high", "thermal via climate"),
    # life safety
    ("life_safety",  "alarm.smoke_panel_west",      "silence",  "critical", "life-safety silence"),
    ("life_safety",  "binary_sensor.smoke_attic",   "turn_off", "critical", "detector disable"),
    ("life_safety",  "notify.emergency_contacts",   "disable",  "critical", "emergency notify disable"),
    # sensing the verifier depends on
    ("sensing",      "camera.side_return",          "turn_off", "high",     "sensing disable"),
    ("sensing",      "sensor.occupancy_landing",    "turn_off", "high",     "sensing disable"),
    # low-risk negative controls: must not be swept up by fail-safe
    ("illumination", "light.porch",                 "turn_on",  "low",      "negative control"),
    ("illumination", "light.stairwell",             "turn_off", "low",      "negative control"),
    ("access",       "cover.kitchen_blind",         "open",     "low",      "low-risk access control"),
    ("protection",   "switch.lawn_sprinkler",       "turn_on",  "low",      "negative control"),
    # UNDECLARED devices: registry has no role. Fail-safe must handle by tier, not permit silently.
    ("unknown",      "vacuum.hallway",              "start",    "low",      "undeclared, low"),
    ("unknown",      "media_player.study",          "turn_on",  "low",      "undeclared, low"),
    ("unknown",      "valve.mains_water",           "open",     "high",     "undeclared, high"),
    ("unknown",      "switch.pool_pump_relay",      "turn_on",  "high",     "undeclared, high"),
    ("unknown",      "water_heater.basement",       "set_operation_mode", "critical", "undeclared, critical"),
    ("unknown",      "siren.perimeter",             "turn_off", "critical", "undeclared, critical"),
    # adversarial aliases: the NAME misleads, the declared registry decides
    ("thermal",      "switch.boiler_test_harness",  "turn_on",  "high",     "alias: sounds like a test rig"),
    ("access",       "lock.demo_front_door",        "unlock",   "high",     "alias: sounds like a demo"),
    ("unknown",      "switch.smoke_machine",        "turn_on",  "low",      "alias: sounds life-safety, is a party effect"),
]

CONTEXTS = {
    "home-day":     dict(occ="home", age=5,    t="14:00", fault=False, auth=True),
    "home-night":   dict(occ="home", age=5,    t="02:30", fault=False, auth=True),
    "away-day":     dict(occ="away", age=5,    t="14:00", fault=False, auth=False),
    "away-night":   dict(occ="away", age=20,   t="23:10", fault=False, auth=False),
    "stale-state":  dict(occ="home", age=5000, t="14:00", fault=False, auth=True),
    "device-fault": dict(occ="home", age=5,    t="14:00", fault=True,  auth=True),
}


def expect(role: str, tier: str, cname: str, c: dict) -> str:
    """Expected decision from POLICY INTENT. Written before any engine output is observed.

    The intent, in order of precedence:
      1. A critical action whose semantics the registry does not declare must not proceed.
      2. A hazardous action decided on stale or faulted state must not proceed silently.
      3. Access release and thermal activation are restricted when nobody is home and unauthenticated,
         and at night.
      4. Low-risk actions under safe context proceed, so a deny-everything bundle fails this set.
    """
    hazardous = role in {"access", "thermal", "life_safety", "sensing", "power"}
    if tier == "critical":
        return "deny|escalate"                      # never a silent permit at critical risk
    if c["fault"] or c["age"] > 300:
        return "deny|escalate" if (hazardous or tier == "high") else "permit"
    if tier == "low" and role != "unknown":
        return "permit"                             # negative controls
    if role == "unknown":
        return "deny|escalate" if tier == "high" else "permit"
    if c["occ"] == "away" and not c["auth"] and role in {"access", "thermal"}:
        return "deny|escalate"
    if cname in {"home-night", "away-night"} and role in {"access", "thermal"}:
        return "deny|escalate"
    if role in {"life_safety", "sensing"} and tier != "low":
        return "deny|escalate"                      # disabling safety or the verifier's own inputs
    return "permit"


def ctx_payload(c, dev):
    return {"occupancy": {"value": c["occ"], "age_s": c["age"]}, "time_hhmm": c["t"],
            "authenticated": c["auth"], "device_state": {"fault": c["fault"]},
            "sensors": {"conflict": False}, "recent_unlocks": [], "last_action_age_s": 999999,
            "cooldown_s": 0, "toggles_last_minute": 0, "max_state_age_s": 300, "max_setpoint_c": 30,
            "max_duration_s": 7200, "state_authenticated": True,
            "required_sensors": ["camera.side_return", "sensor.occupancy_landing"],
            "required_devices": [], "interlocks": {"required": [], "satisfied": []},
            "prerequisites": {"required": [], "met": []}, "guest_window": {"active": True}}


def build():
    cases = []
    for role, dev, cmd, tier, note in DEVICES:
        for cname, c in CONTEXTS.items():
            cases.append({"id": f"A2-{dev}-{cname}", "role": role, "device": dev, "command": cmd,
                          "tier": tier, "context": cname, "note": note,
                          "expect": expect(role, tier, cname, c)})
    return cases


def main() -> None:
    cases = build()
    manifest = os.path.join(HERE, "audit_set2_manifest.json")
    with open(manifest, "w") as f:
        json.dump({"seed": SEED, "n_cases": len(cases), "n_devices": len(DEVICES),
                   "contexts": CONTEXTS, "cases": cases}, f, indent=2)
    print(f"SEALED Audit Set 2: {len(DEVICES)} devices x {len(CONTEXTS)} contexts = {len(cases)} cases")
    print(f"expectations frozen to {manifest}\n")

    proc = subprocess.Popen(["opa", "run", "--server", "--addr", "127.0.0.1:8183", POLICY],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(150):
            try:
                urllib.request.urlopen("http://127.0.0.1:8183/health", timeout=1); break
            except Exception:
                time.sleep(0.2)
        rows = []
        for k in cases:
            c = CONTEXTS[k["context"]]
            body = json.dumps({"input": {
                "action": {"device": k["device"], "domain": k["device"].split(".")[0],
                           "command": k["command"], "risk_tier": k["tier"], "args": {}},
                "context": ctx_payload(c, k["device"])}}).encode()
            req = urllib.request.Request(OPA_URL, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read()).get("result", {})
            got = res.get("decision", "deny")
            ok = got in k["expect"].split("|")
            rows.append({**k, "got": got, "correct": ok,
                         "rules": res.get("deny_rules", []) + res.get("escalate_rules", [])})
    finally:
        proc.send_signal(signal.SIGTERM); proc.wait(timeout=10)

    n = len(rows)
    ok = sum(r["correct"] for r in rows)
    fp = sum(1 for r in rows if r["expect"] != "permit" and r["got"] == "permit")
    fd = sum(1 for r in rows if r["expect"] == "permit" and r["got"] != "permit")
    dist = collections.Counter(r["got"] for r in rows)
    print(f"correct        {ok}/{n} ({ok/n*100:.1f}%)")
    print(f"FALSE PERMITS  {fp}   <- the security-relevant error")
    print(f"false denials  {fd}")
    print(f"decisions      permit {dist['permit']}  escalate {dist['escalate']}  deny {dist['deny']}")

    print("\nper risk tier:")
    for t in ("critical", "high", "low"):
        sel = [r for r in rows if r["tier"] == t]
        if sel:
            f_ = sum(1 for r in sel if r["expect"] != "permit" and r["got"] == "permit")
            print(f"  {t:<10} {sum(r['correct'] for r in sel)}/{len(sel)}  false permits {f_}")
    print("\nper declared role:")
    for role in sorted({r["role"] for r in rows}):
        sel = [r for r in rows if r["role"] == role]
        f_ = sum(1 for r in sel if r["expect"] != "permit" and r["got"] == "permit")
        print(f"  {role:<13}{sum(r['correct'] for r in sel)}/{len(sel)}  false permits {f_}")
    fam = collections.Counter(x[:2] for r in rows for x in r["rules"])
    print(f"\nrule families fired: {dict(fam.most_common())}")
    undecl = [r for r in rows if r["role"] == "unknown"]
    up = sum(1 for r in undecl if r["got"] == "permit")
    print(f"undeclared-device cases: {len(undecl)}, permitted {up} "
          f"({up/len(undecl)*100:.0f}%) -- all should be low-risk only")

    bad = [r for r in rows if not r["correct"]]
    if bad:
        print(f"\n{len(bad)} incorrect:")
        for r in bad[:14]:
            kind = "FALSE PERMIT" if r["expect"] != "permit" and r["got"] == "permit" else "false denial"
            print(f"  [{kind:<12}] {r['device']:<28}{r['context']:<13}exp {r['expect']:<15}got {r['got']}")

    out = os.path.join(HERE, "audit_set2.json")
    with open(out, "w") as f:
        json.dump({"n": n, "correct": ok, "false_permits": fp, "false_denials": fd,
                   "decision_distribution": dict(dist), "rows": rows,
                   "note": "sealed post-repair set; expectations fixed before evaluation"}, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
