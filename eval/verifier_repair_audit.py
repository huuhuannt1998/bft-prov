"""E8: repair the six Audit Set 2 false permits, then regress both frozen suites.

Revision plan R11 / E8. Audit Set 2 scored 140/150 with 6 false permits and 4 false denials, and the
manuscript reports that frozen result without repairing it. One of the false permits is "disable
emergency notification", a critical-tier action. This script diagnoses all ten failures, then scores
the repaired bundle against both frozen suites.

WHAT IS COMPARED
  bundle "before" = agent/guard/verifier.rego.pre-e8   (the bundle the manuscript reports)
  bundle "after"  = agent/guard/verifier.rego          (the E8 repair)

  suite "conformance" = eval.verifier_eval.corpus(), 42 cases, exact-match expectations.
                        Rule-engine conformance: does the implementation execute the installed rules.
  suite "audit2"      = eval.audit_set2.build(), 150 cases (25 devices x 6 contexts), expectations
                        written from policy intent and sealed before the engine was ever run. Both
                        the case list and the expectation function are imported unchanged, so the
                        sealed expectations are the ones being scored.

  registry arm "off" = context carries no device_registry; role resolution falls back to the built-in
                       entity-id prefix table, exactly as before E8.
  registry arm "on"  = context carries the sealed manifest's own role column as gateway-supplied
                       enrolment state (E8 repair R-E8-4).

HONESTY NOTE, to be carried into the manuscript verbatim.
Audit Set 2 drove this repair, so after this script runs it is a DIAGNOSTIC set exactly as the 54-case
Audit Set 1 became one. Its post-repair score measures that the repair did what it was aimed at; it is
not held-out evidence and must not be reported as such. Audit Set 3 (eval/audit_set3.py,
eval/audit_set3_protocol.md) is the held-out successor.

Usage: PYTHONPATH=. python -m eval.verifier_repair_audit
"""
from __future__ import annotations

import collections
import json
import os
import re
import signal
import subprocess
import time
import urllib.request

from eval import verifier_eval
from eval.audit_set2 import CONTEXTS, DEVICES, build, ctx_payload

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUNDLES = {"before": os.path.join(ROOT, "agent", "guard", "verifier.rego.pre-e8"),
           "after": os.path.join(ROOT, "agent", "guard", "verifier.rego")}
PORT = 8191
SEED = 20260801

# The sealed manifest's role column, keyed by entity id. This is the operator enrolment record a
# deployment would hold; here it is read straight off the frozen DEVICES table, so it carries no
# information that was not already sealed before the engine first ran.
REGISTRY = {dev: role for role, dev, _cmd, _tier, _note in DEVICES}


class OPA:
    def __init__(self, policy: str, port: int):
        self.policy, self.port = policy, port
        self.url = f"http://127.0.0.1:{port}/v1/data/pqbftprov/verifier/result"

    def __enter__(self):
        self.p = subprocess.Popen(
            ["opa", "run", "--server", "--addr", f"127.0.0.1:{self.port}", self.policy],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(200):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1)
                return self
            except Exception:
                time.sleep(0.2)
        raise RuntimeError(f"opa did not come up for {self.policy}")

    def __exit__(self, *a):
        self.p.send_signal(signal.SIGTERM)
        self.p.wait(timeout=10)

    def eval(self, action, context):
        body = json.dumps({"input": {"action": action, "context": context}}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("result", {})


# ---------------------------------------------------------------- suites

def run_conformance(srv) -> list[dict]:
    """42-case policy-intent suite. Expectations are exact-match, as in eval.verifier_eval."""
    rows = []
    for c in verifier_eval.corpus():
        r = srv.eval(c["action"], c["context"])
        got = r.get("decision", "?")
        rows.append({"id": c["id"], "family": c["family"], "kind": c["kind"],
                     "expect": c["expect"], "got": got, "correct": got == c["expect"],
                     "rules": r.get("deny_rules", []) + r.get("escalate_rules", [])})
    return rows


def run_audit2(srv, registry: bool) -> list[dict]:
    """150-case sealed Audit Set 2. `expect` uses the deny|escalate convention of audit_set2.py."""
    rows = []
    for k in build():
        c = CONTEXTS[k["context"]]
        context = ctx_payload(c, k["device"])
        if registry:
            context["device_registry"] = REGISTRY
        r = srv.eval({"device": k["device"], "domain": k["device"].split(".")[0],
                      "command": k["command"], "risk_tier": k["tier"], "args": {}}, context)
        got = r.get("decision", "deny")
        rows.append({**k, "got": got, "correct": got in k["expect"].split("|"),
                     "rules": r.get("deny_rules", []) + r.get("escalate_rules", []),
                     "engine_role": r.get("device_role"), "semantic_class": r.get("semantic_class")})
    return rows


def confusion(rows) -> dict:
    """Counts over the {permit, escalate, deny} lattice plus the two error classes that matter."""
    n = len(rows)
    fp = [r["id"] for r in rows if r["expect"] != "permit" and r["got"] == "permit"]
    fd = [r["id"] for r in rows if r["expect"] == "permit" and r["got"] != "permit"]
    other = [r["id"] for r in rows if not r["correct"] and r["id"] not in fp and r["id"] not in fd]
    cells = collections.Counter((r["expect"], r["got"]) for r in rows)
    return {"n": n, "correct": sum(r["correct"] for r in rows),
            "false_permits": len(fp), "false_denials": len(fd), "other_incorrect": len(other),
            "false_permit_ids": fp, "false_denial_ids": fd, "other_incorrect_ids": other,
            "decision_distribution": dict(collections.Counter(r["got"] for r in rows)),
            "matrix_expect_by_got": {f"{e} -> {g}": c for (e, g), c in sorted(cells.items())}}


# ---------------------------------------------------------------- bundle self-check

def bundle_selfcheck(path: str) -> dict:
    """R-E8-3's standing invariant: every hazard class names >=1 governing rule, and every named
    rule id is actually defined in the bundle. This is what stops the next role added to role_table
    from silently recreating a declared-but-ungoverned permissive class."""
    src = open(path).read()

    def block(name):
        m = re.search(name + r"\s*:=\s*\{(.*?)\n\}", src, re.S)
        return m.group(1) if m else ""

    hazard = set(re.findall(r'"([a-z_]+\.[a-z_]+)"', block("hazard_classes")))
    gov_src = block("class_governors")
    governors = {c: set(re.findall(r'"([A-Z]{2}\d+)"', body))
                 for c, body in re.findall(r'"([a-z_]+\.[a-z_]+)":\s*\{([^}]*)\}', gov_src)}
    defined = set(re.findall(r'(?:deny_rules|escalate_rules|residual_deny|residual_escalate)'
                            r'\s+contains\s+"([A-Z]{2}\d+)"', src))
    ungoverned = sorted(c for c in hazard if not governors.get(c))
    dangling = sorted({r for rs in governors.values() for r in rs} - defined)
    return {"hazard_classes": sorted(hazard), "n_rules_defined": len(defined),
            "rules_defined": sorted(defined),
            "governors": {c: sorted(v) for c, v in sorted(governors.items())},
            "hazard_classes_without_governor": ungoverned,
            "governor_ids_not_defined_in_bundle": dangling,
            "passed": not ungoverned and not dangling}


# ---------------------------------------------------------------- reporting

def diag_table(before_rows, after_off, after_on):
    """One row per case that the pre-repair bundle got wrong: what it did, and what each arm now does."""
    b = {r["id"]: r for r in before_rows}
    a0 = {r["id"]: r for r in after_off}
    a1 = {r["id"]: r for r in after_on}
    out = []
    for rid, r in b.items():
        if r["correct"]:
            continue
        kind = "FALSE PERMIT" if r["expect"] != "permit" and r["got"] == "permit" else "false denial"
        out.append({"id": rid, "kind": kind, "device": r["device"], "context": r["context"],
                    "tier": r["tier"], "command": r["command"], "declared_role": r["role"],
                    "expect": r["expect"],
                    "before_got": r["got"], "before_rules": r["rules"],
                    "before_engine_role": r.get("engine_role"),
                    "after_got": a0[rid]["got"], "after_rules": a0[rid]["rules"],
                    "after_registry_got": a1[rid]["got"], "after_registry_rules": a1[rid]["rules"],
                    "fixed_by_rules": a0[rid]["correct"], "fixed_with_registry": a1[rid]["correct"]})
    return out


def hline(t=""):
    print(f"\n{'=' * 96}\n{t}" if t else "=" * 96)


def main() -> None:
    res = {}
    with OPA(BUNDLES["before"], PORT) as srv:
        res["before_conformance"] = run_conformance(srv)
        res["before_audit2_registry_off"] = run_audit2(srv, registry=False)
        res["before_audit2_registry_on"] = run_audit2(srv, registry=True)
    with OPA(BUNDLES["after"], PORT + 1) as srv:
        res["after_conformance"] = run_conformance(srv)
        res["after_audit2_registry_off"] = run_audit2(srv, registry=False)
        res["after_audit2_registry_on"] = run_audit2(srv, registry=True)

    conf = {k: confusion(v) for k, v in res.items()}
    check = bundle_selfcheck(BUNDLES["after"])

    hline("(1) ENUMERATION -- the ten Audit Set 2 failures the manuscript reports, with root cause")
    print(f"{'kind':<13}{'device':<28}{'ctx':<12}{'tier':<9}{'exp':<15}{'got':<9}"
          f"{'engine role':<13}rules fired")
    for r in res["before_audit2_registry_off"]:
        if r["correct"]:
            continue
        k = "FALSE PERMIT" if r["expect"] != "permit" and r["got"] == "permit" else "false denial"
        print(f"{k:<13}{r['device']:<28}{r['context']:<12}{r['tier']:<9}{r['expect']:<15}"
              f"{r['got']:<9}{str(r['engine_role']):<13}{r['rules'] or '(none)'}")

    hline("(3)/(4) REGRESSION -- confusion counts, before vs after")
    print(f"{'arm':<40}{'n':>5}{'correct':>9}{'FALSE PERMITS':>15}{'false denials':>15}")
    for k in ("before_conformance", "after_conformance",
              "before_audit2_registry_off", "after_audit2_registry_off",
              "before_audit2_registry_on", "after_audit2_registry_on"):
        c = conf[k]
        print(f"{k:<40}{c['n']:>5}{c['correct']:>9}{c['false_permits']:>15}{c['false_denials']:>15}")

    hline("per-case outcome for the ten")
    print(f"{'kind':<13}{'device':<28}{'ctx':<12}{'before':<10}{'after':<10}{'after+reg':<11}fixed?")
    dt = diag_table(res["before_audit2_registry_off"], res["after_audit2_registry_off"],
                    res["after_audit2_registry_on"])
    for d in dt:
        tag = ("rules" if d["fixed_by_rules"] else
               ("registry" if d["fixed_with_registry"] else "NOT FIXED"))
        print(f"{d['kind']:<13}{d['device']:<28}{d['context']:<12}{d['before_got']:<10}"
              f"{d['after_got']:<10}{d['after_registry_got']:<11}{tag}")

    hline("regressions introduced by the repair (cases correct before, wrong after)")
    for suite in ("conformance", "audit2_registry_off", "audit2_registry_on"):
        b = {r["id"]: r for r in res[f"before_{suite}"]}
        a = {r["id"]: r for r in res[f"after_{suite}"]}
        reg = [i for i in b if b[i]["correct"] and not a[i]["correct"]]
        chg = [i for i in b if b[i]["got"] != a[i]["got"]]
        print(f"  {suite:<24} new failures {len(reg)}  decisions changed {len(chg)}")
        for i in reg:
            print(f"      REGRESSION {i}: exp {b[i]['expect']} was {b[i]['got']} now {a[i]['got']}")

    hline("(3) BUNDLE SELF-CHECK -- every hazard class must name a governing rule that exists")
    print(f"  rules defined in bundle            {check['n_rules_defined']}")
    print(f"  hazard classes                     {len(check['hazard_classes'])}")
    print(f"  hazard classes with no governor    {check['hazard_classes_without_governor'] or 'none'}")
    print(f"  governor ids not defined in bundle {check['governor_ids_not_defined_in_bundle'] or 'none'}")
    print(f"  SELF-CHECK {'PASSED' if check['passed'] else 'FAILED'}")

    hline()
    print("DISCIPLINE. Audit Set 2 drove this repair. It is now a diagnostic set, exactly as the")
    print("54-case Audit Set 1 became one after it drove the previous repair. The post-repair score")
    print("below measures that the repair did what it was aimed at; it is NOT held-out evidence.")
    print("The held-out successor is Audit Set 3 (eval/audit_set3.py, eval/audit_set3_protocol.md),")
    print("whose expected decisions are adjudicated by someone other than the rule author.")

    out = os.path.join(HERE, "verifier_repair_audit.json")
    with open(out, "w") as f:
        json.dump({
            "seed": SEED,
            "bundles": {k: os.path.relpath(v, ROOT) for k, v in BUNDLES.items()},
            "n_rules_before": 24, "n_rules_after": check["n_rules_defined"],
            "confusion": conf,
            "bundle_selfcheck": check,
            "failure_diagnosis": dt,
            "rows": res,
            "discipline_note": (
                "Audit Set 2 drove this repair and is therefore diagnostic, not held out. Its "
                "post-repair score measures that the repair did what it was aimed at. Audit Set 3 "
                "is the held-out successor, with externally adjudicated expected decisions."),
        }, f, indent=2)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
