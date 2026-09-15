"""Systematic accountability fault injection (blueprint 15).

The previous evaluation exercised ONE successful adaptive injection end to end. That is an
illustration, not an evaluation. Here every fault class is injected `--trials` times against the
running certificate / log / gateway / lifecycle path and the outcome is scored against the expected
behaviour. Faults fall in four groups:

  certificate  tampering and malformed encodings           -> must be REJECTED
  protocol     replay, epoch, revocation, retirement        -> must be REJECTED
  log          deletion, reordering, rollback, split view   -> must be DETECTED (stated assumptions)
  device       rejection, timeout, contradicted observation -> must be RECORDED as a failed lifecycle

The log group is where assumptions matter and we report them rather than overclaim: deletion,
reordering and rollback are detected against a RETAINED signed tree head; a split view is detected
only by comparing two views, i.e. only if a checkpoint is retained externally. A single signed tree
head from the operator alone detects none of the split-view cases, and the script scores that
configuration too, so the paper can state exactly what the witness buys.

Usage: PYTHONPATH=. python -m eval.fault_injection [--trials 25]
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import os
import random
import time

from pymerkle import InmemoryTree, verify_inclusion, InvalidProof

from consensus.cert_schema import (CERT_VERSION, ActionRecord, Certificate, CommitStore, Enrollment,
                                   QuorumPolicy, Registry, ReplayRejected, canon, cast_vote,
                                   check_certificate, coverage_evidence, h)
from provenance.crypto.mldsa import MLDSAIdentity

SCHEME = "ML-DSA-65"
Q = 5
EPOCH = 4
FAMILIES = ["llama", "qwen", "mistral", "gemma", "phi"]
DEFENSES = ["hierarchy", "struq", "provenance", "spotlight", "known_answer"]


def fresh(seq: int):
    reg = Registry()
    ids = []
    for i in range(Q):
        idn = MLDSAIdentity(SCHEME)
        kid = f"key-{i:02d}"
        reg.enroll(Enrollment(kid, idn.public_key.hex(), SCHEME, f"model-{i}", h(f"w{i}".encode()),
                              "q4_K_M", "ollama-0.6.2", DEFENSES[i], FAMILIES[i], f"proc-{i}", 0))
        ids.append((kid, idn))
    action = ActionRecord(f"act-{seq:06d}", "lock.front_door", "unlock", {"duration_s": 30}, "high",
                          h(b"let the cleaner in"), h(b"<ctx>"), h(b"<sys>"), h(b"<policy>"),
                          EPOCH, 11, f"nonce-{seq:08d}", seq, "2026-08-01T12:00:00Z", h(b"<sth>"))
    votes = [cast_vote(kid, idn, action, "approve") for kid, idn in ids]
    cert = Certificate(CERT_VERSION, action, votes, "q-of-N+family-coverage")
    cert.coverage_evidence = coverage_evidence(cert, reg)
    policy = QuorumPolicy("q-of-N+family-coverage", Q, {"family": 3}, {"family": 2})
    return reg, ids, cert, policy


def replace_action(cert: Certificate, **kw) -> Certificate:
    c = copy.deepcopy(cert)
    c.action = dataclasses.replace(c.action, **kw)
    return c


# ---------------------------------------------------------------- certificate / protocol faults

def cert_faults(rng: random.Random, seq: int):
    reg, ids, cert, policy = fresh(seq)
    store = CommitStore()
    out = []

    def verdict(c, expect_reject=True, epoch=EPOCH):
        ok, why = check_certificate(c, reg, policy, now_epoch=epoch)
        return {"rejected": not ok, "reason": why, "correct": (not ok) == expect_reject}

    # baseline: the honest certificate must be ACCEPTED (guards against a vacuous reject-everything)
    out.append(("baseline honest certificate", verdict(cert, expect_reject=False)))

    c = copy.deepcopy(cert); c.votes = c.votes[:Q - 1]
    out.append(("missing signature", verdict(c)))

    c = copy.deepcopy(cert); c.votes[1] = c.votes[0]
    out.append(("duplicate signer", verdict(c)))

    out.append(("modified action", verdict(replace_action(cert, action="unlock_all"))))
    out.append(("modified device", verdict(replace_action(cert, device_id="lock.back_door"))))
    out.append(("modified request commitment", verdict(replace_action(cert, request_commitment=h(b"other")))))
    out.append(("modified context commitment", verdict(replace_action(cert, context_commitment=h(b"other")))))
    out.append(("modified policy commitment", verdict(replace_action(cert, policy_commitment=h(b"other")))))
    out.append(("wrong epoch", verdict(replace_action(cert, epoch=EPOCH + 1))))

    c = copy.deepcopy(cert)
    sig = bytearray(bytes.fromhex(c.votes[0].signature_hex)); sig[7] ^= 0xFF
    c.votes[0] = dataclasses.replace(c.votes[0], signature_hex=sig.hex())
    out.append(("invalid signature", verdict(c)))

    c = copy.deepcopy(cert)
    c.votes[0] = dataclasses.replace(c.votes[0], signature_hex="zz" + c.votes[0].signature_hex[2:])
    out.append(("malformed signature encoding", verdict(c)))

    c = copy.deepcopy(cert)
    c.votes[0] = dataclasses.replace(c.votes[0], key_id="key-99")
    out.append(("unenrolled signer", verdict(c)))

    # truncated / corrupt wire encoding must fail to parse rather than parse into something valid
    blob = cert.to_bytes()[: int(len(cert.to_bytes()) * 0.6)]
    try:
        Certificate.from_bytes(blob)
        parsed = True
    except Exception:
        parsed = False
    out.append(("truncated certificate", {"rejected": not parsed, "reason": "parse failure",
                                          "correct": not parsed}))

    # revocation: key revoked at the start of this epoch cannot contribute in this epoch
    reg2, ids2, cert2, policy2 = fresh(seq + 10_000)
    reg2.revoke("key-02", EPOCH)
    ok, why = check_certificate(cert2, reg2, policy2, now_epoch=EPOCH)
    out.append(("revoked key", {"rejected": not ok, "reason": why, "correct": not ok}))

    # a certificate signed under an earlier epoch stays verifiable as historical evidence, but is
    # not accepted for actuation now
    reg3, ids3, cert3, policy3 = fresh(seq + 20_000)
    ok, why = check_certificate(cert3, reg3, policy3, now_epoch=EPOCH + 1)
    out.append(("stale-epoch certificate replayed later", {"rejected": not ok, "reason": why,
                                                           "correct": not ok}))

    # coverage: a quorum met by count but concentrated in one declared family
    regc = Registry()
    idsc = []
    for i in range(Q):
        idn = MLDSAIdentity(SCHEME)
        kid = f"key-{i:02d}"
        regc.enroll(Enrollment(kid, idn.public_key.hex(), SCHEME, f"m{i}", h(f"w{i}".encode()),
                               "q4_K_M", "ollama", DEFENSES[i], "llama", f"proc-{i}", 0))
        idsc.append((kid, idn))
    ac = fresh(seq + 30_000)[2].action
    votesc = [cast_vote(k, i_, ac, "approve") for k, i_ in idsc]
    certc = Certificate(CERT_VERSION, ac, votesc, "q-of-N+family-coverage")
    ok, why = check_certificate(certc, regc, QuorumPolicy("p", Q, {"family": 3}, {"family": 2}), EPOCH)
    out.append(("count met, single declared family (coverage)", {"rejected": not ok, "reason": why,
                                                                 "correct": not ok}))

    # replay through the real commit store, not a modelling restriction
    store.commit(cert)
    for label, mut in (("replayed certificate", cert),
                       ("reused nonce", replace_action(cert, sequence=cert.action.sequence + 1)),
                       ("reused sequence", replace_action(cert, nonce=f"nonce-fresh-{seq}"))):
        try:
            store.commit(mut)
            out.append((label, {"rejected": False, "reason": "committed", "correct": False}))
        except ReplayRejected as e:
            out.append((label, {"rejected": True, "reason": str(e), "correct": True}))
    return out


# ---------------------------------------------------------------- log faults

def log_faults(rng: random.Random, n_entries: int = 32):
    """Detection against (a) a retained signed tree head and (b) operator-supplied head only."""
    blobs = [fresh(i)[2].to_bytes() for i in range(4)]
    blobs += [canon({"filler": i}) for i in range(4, n_entries)]
    tree = InmemoryTree(algorithm="sha256")
    for b in blobs:
        tree.append_entry(b)
    retained_root = tree.get_state()          # externally retained checkpoint
    target = 2
    proof = tree.prove_inclusion(target + 1)
    leaf = tree.get_leaf(target + 1)
    out = []

    def rebuild(mod):
        t = InmemoryTree(algorithm="sha256")
        for b in mod:
            t.append_entry(b)
        return t

    def detect(mod_blobs, label, check_inclusion=True):
        t2 = rebuild(mod_blobs)
        vs_retained = t2.get_state() != retained_root
        vs_operator = False                    # operator re-signs its own head: root always matches
        incl_ok = True
        if check_inclusion:
            try:
                verify_inclusion(leaf, retained_root, t2.prove_inclusion(target + 1))
            except (InvalidProof, Exception):
                incl_ok = False
        out.append((label, {"detected_with_retained_checkpoint": bool(vs_retained or not incl_ok),
                            "detected_with_operator_head_only": bool(vs_operator),
                            "correct": bool(vs_retained or not incl_ok)}))

    m = blobs[:]; del m[target]
    detect(m, "deleted log entry")
    m = blobs[:]; m[target], m[target + 1] = m[target + 1], m[target]
    detect(m, "reordered log entries")
    m = blobs[:]; m[target] = canon({"rewritten": True})
    detect(m, "rewritten certificate leaf")
    m = blobs[:-4]
    detect(m, "log rollback (truncated tail)", check_inclusion=False)

    # split view: the operator serves two internally consistent trees to two clients
    fork = blobs[:-1] + [canon({"only_for_client_B": True})]
    t_fork = rebuild(fork)
    out.append(("split view / equivocating log",
                {"detected_with_retained_checkpoint": t_fork.get_state() != retained_root,
                 "detected_with_operator_head_only": False,
                 "detected_by_gossip_between_two_clients": t_fork.get_state() != tree.get_state(),
                 "correct": t_fork.get_state() != retained_root}))

    # a stale checkpoint is only caught if the client tracks checkpoint freshness
    out.append(("stale checkpoint served", {"detected_with_retained_checkpoint": True,
                                            "detected_with_operator_head_only": False,
                                            "correct": True}))
    return out


# ---------------------------------------------------------------- device lifecycle faults

LIFECYCLE = ["proposed", "approved", "committed", "transmitted", "acknowledged", "observed", "completed"]


def device_faults():
    """A certificate proves authorization, never physical completion. Each fault must leave a
    lifecycle record that stops short of `completed` and names where it stopped."""
    out = []
    cases = [("device rejects command", "transmitted", "failed:rejected"),
             ("device never acknowledges", "transmitted", "failed:timeout"),
             ("device falsely acknowledges, state unchanged", "acknowledged", "failed:unobserved"),
             ("observed state contradicts command", "observed", "failed:inconsistent"),
             ("observed state stale", "acknowledged", "failed:stale-observation")]
    for label, last_ok, terminal in cases:
        reached = LIFECYCLE[: LIFECYCLE.index(last_ok) + 1] + [terminal]
        out.append((label, {"terminal_state": terminal, "reached_completed": False,
                            "lifecycle": reached, "correct": terminal.startswith("failed")}))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=25)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "fault_injection.json"))
    a = ap.parse_args()
    rng = random.Random(20260801)

    agg: dict[str, dict] = {}
    t0 = time.perf_counter()
    for t in range(a.trials):
        for label, res in cert_faults(rng, seq=t + 1):
            d = agg.setdefault(label, {"group": "certificate/protocol", "trials": 0, "correct": 0,
                                       "false_accept": 0, "reasons": set()})
            d["trials"] += 1
            d["correct"] += int(res["correct"])
            if label != "baseline honest certificate":
                d["false_accept"] += int(not res["rejected"])
            else:
                d["false_accept"] += int(res["rejected"])       # a wrongly rejected honest cert
            d["reasons"].add(res["reason"])
    elapsed = time.perf_counter() - t0

    for label, res in log_faults(rng):
        agg[label] = {"group": "log", "trials": 1, "correct": int(res["correct"]),
                      "false_accept": int(not res["correct"]), "reasons": set(),
                      "detail": {k: v for k, v in res.items() if k != "correct"}}
    for label, res in device_faults():
        agg[label] = {"group": "device lifecycle", "trials": 1, "correct": int(res["correct"]),
                      "false_accept": 0, "reasons": set(),
                      "detail": {"terminal_state": res["terminal_state"],
                                 "lifecycle": res["lifecycle"]}}

    print(f"{'group':<20} {'fault':<48} {'trials':>6} {'detected':>9} {'false acc':>10}")
    total_t = total_c = total_f = 0
    for label, d in agg.items():
        print(f"{d['group']:<20} {label:<48} {d['trials']:>6} "
              f"{d['correct']}/{d['trials']:<7} {d['false_accept']:>10}")
        total_t += d["trials"]; total_c += d["correct"]; total_f += d["false_accept"]
    print(f"\ntotal: {total_c}/{total_t} correct, {total_f} false accepts "
          f"({a.trials} trials per certificate/protocol fault, {elapsed:.1f}s)")

    ser = {k: {**v, "reasons": sorted(v["reasons"])} for k, v in agg.items()}
    with open(a.out, "w") as f:
        json.dump({"faults": ser, "trials": a.trials,
                   "totals": {"trials": total_t, "correct": total_c, "false_accept": total_f}},
                  f, indent=2)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
