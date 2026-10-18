"""request_trace.py -- worked example: successive requests at one verifier.

Takes the depth-4 IoMT demo chain (cloud -> fog -> gateway -> device ->
sensor; topic ward3/bed12/vitals/hr, 12 exercises per minute) and feeds a fixed sequence of
requests to a RequestVerifier with an evidence log attached. Each row of the
output is one request and the verdict the verifier reached, in order. The
sequence exercises acceptance, replay, a request without proof of possession
of the leaf key, a topic outside scope, the rate window filling and sliding,
and revocation by epoch. Deterministic: fixed keys, fixed clock values.

Outputs:
  data/request_trace.csv
"""

from __future__ import annotations

import csv
import hashlib
import os

import contgrant as cg

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
os.makedirs(DATA, exist_ok=True)

DEPTH = 4
T0 = 1_700_000_500  # inside the chain's validity window
BED12 = (52.5201, 13.4051)  # the verifier's own record of the device position


def run() -> list[dict]:
    chain, anchor, _ = cg._demo_chain(DEPTH)
    leaf = cg._demo_key(DEPTH)
    parent = cg._demo_key(DEPTH - 1)  # the device that delegated to the sensor
    log = cg.EvidenceLog(cg._demo_key(1))  # fog node's writer key
    rv = cg.RequestVerifier(anchor, boot_time=T0 - 3600, evidence=log)
    digest = cg.chain_digest(chain)
    rows: list[dict] = []

    def send(step, dt, ctr, signer, signer_name, topic="ward3/bed12/vitals/hr",
             note="", replay_of=None):
        if replay_of is not None:
            req, sig = replay_of
        else:
            payload = hashlib.sha256(f"hr reading {ctr}".encode()).digest()
            req = cg.Request(digest, topic, payload, ctr, T0 + dt)
            sig = cg.sign_request(signer, req)
        allowed = rv.decide(chain, req, sig, T0 + dt, BED12)
        rec = log.records[-1]["body"]
        rows.append({
            "step": step,
            "t_s": dt,
            "counter": req.counter,
            "signed_by": signer_name,
            "topic": req.topic,
            "note": note,
            "verdict": "allow" if allowed else "deny",
            "reason": rec["reason"],
            "evidence_seq": rec["seq"],
        })
        return req, sig

    first = send(1, 0, 1, leaf, "sensor")
    send(2, 1, 1, leaf, "sensor", note="replay of step 1", replay_of=first)
    send(3, 2, 2, parent, "device", note="parent key, not the leaf key")
    send(4, 3, 2, leaf, "sensor", topic="ward3/bed12/meds/rate")
    for i in range(10):  # exercises 2..11 inside the minute
        send(5, 4 + i, 3 + i, leaf, "sensor", note="10 requests")
    rows[-10:] = [rows[-1] | {"t_s": "4-13", "counter": "3-12"}]
    send(6, 14, 13, leaf, "sensor", note="12th exercise in the minute")
    send(7, 15, 14, leaf, "sensor", note="13th in the minute")
    send(8, 61, 15, leaf, "sensor", note="step 1 has left the window")
    rv.install_epoch(cg.sign_epoch(cg._demo_key(0), 1, {cg.hop_id(chain.hops[2])}))
    send(9, 62, 16, leaf, "sensor", note="after epoch 1")

    seq, head = log.anchor()
    assert cg.verify_evidence(log.records, log.writer_pub, ((seq, head),)) == head
    return rows


if __name__ == "__main__":
    rows = run()
    path = os.path.join(DATA, "request_trace.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}  ({len(rows)} rows)")
    for r in rows:
        print(f"  {r['step']:>2} t={r['t_s']!s:>5} ctr={r['counter']!s:>5} "
              f"{r['signed_by']:8s} {r['verdict']:5s} {r['reason']}")
