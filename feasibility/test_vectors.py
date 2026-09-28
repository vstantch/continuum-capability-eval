"""test_vectors.py -- correctness gate for contgrant.

Golden (must-accept) vectors: valid chains at depths 1,2,3,4,6.
Violation (must-reject) vectors: broadened topic prefix, widened window,
increased rate, geofence escape, wrong child key, tampered payload, expired,
action outside caveats.

Run with:  pytest test_vectors.py        (or)   python3 test_vectors.py
Every violation MUST be rejected; every valid vector MUST be accepted.
"""

from __future__ import annotations

import copy
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import contgrant as cg
from contgrant import (
    Action,
    Caveats,
    ChainBuilder,
    VerificationError,
    raw_pub,
    verify_chain,
    encode_json,
    decode_json,
    encode_cbor,
    decode_cbor,
    _demo_chain,
)


def mkkey(i: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes((i * 13 + j) % 256 for j in range(32)))


# ---------------------------------------------------------------------------
# GOLDEN: valid chains at depths 1,2,3,4,6 accepted (both encodings).
# ---------------------------------------------------------------------------
def test_golden_valid_depths():
    for depth in (1, 2, 3, 4, 6):
        chain, anchor, action = _demo_chain(depth)
        eff = verify_chain(chain, anchor, action)
        assert eff is not None
        # both wire encodings round-trip and still verify
        assert verify_chain(decode_json(encode_json(chain)), anchor, action)
        assert verify_chain(decode_cbor(encode_cbor(chain)), anchor, action)


# ---------------------------------------------------------------------------
# Helper to build a clean 3-hop chain we can then corrupt.
# ---------------------------------------------------------------------------
def build_base_chain():
    root = mkkey(0)
    k1, k2, k3 = mkkey(1), mkkey(2), mkkey(3)
    b = ChainBuilder(root)
    c0 = Caveats(
        topic_prefix="ward3/",
        rate_limit_per_min=120,
        geofence=(52.5200, 13.4050, 500.0),
        valid_from=1_700_000_000,
        valid_until=1_700_000_000 + 7 * 24 * 3600,
    )
    c1 = replace(c0, topic_prefix="ward3/bed12/", rate_limit_per_min=60,
                 geofence=(52.5200, 13.4050, 200.0))
    c2 = replace(c0, topic_prefix="ward3/bed12/vitals/", rate_limit_per_min=30,
                 geofence=(52.5201, 13.4051, 80.0),
                 valid_until=1_700_000_000 + 2 * 24 * 3600)
    b.add_hop("cloud", "fog", k1, c0)
    b.add_hop("fog", "gateway", k2, c1)
    b.add_hop("gateway", "device", k3, c2)
    chain = b.build()
    anchor = chain.root_pub
    action = Action(topic="ward3/bed12/vitals/hr", time=1_700_000_500,
                    location=(52.5201, 13.4051), rate_slot=5)
    keys = (root, k1, k2, k3)
    caveats = (c0, c1, c2)
    return chain, anchor, action, keys, caveats


def test_base_chain_accepts():
    chain, anchor, action, _, _ = build_base_chain()
    assert verify_chain(chain, anchor, action)


def _expect_reject(chain, anchor, action=None):
    try:
        verify_chain(chain, anchor, action)
    except VerificationError:
        return
    raise AssertionError("expected VerificationError but chain verified")


# ---------------------------------------------------------------------------
# VIOLATION 1: broadened topic prefix (child no longer extends parent).
# ---------------------------------------------------------------------------
def test_violation_broadened_topic():
    chain, anchor, action, keys, caveats = build_base_chain()
    root, k1, k2, k3 = keys
    # Rebuild hop 2 with a broader (non-extending) topic prefix, re-signed
    # correctly by its parent so ONLY the attenuation check can catch it.
    bad = replace(caveats[2], topic_prefix="ward/")  # not a superstring-extend
    chain.hops[2].caveats = bad
    chain.hops[2].sign(k2)  # legit signature by parent k2
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 2: widened validity window (child valid_until beyond parent).
# ---------------------------------------------------------------------------
def test_violation_widened_window():
    chain, anchor, action, keys, caveats = build_base_chain()
    root, k1, k2, k3 = keys
    bad = replace(caveats[2], valid_until=1_700_000_000 + 30 * 24 * 3600)  # widens
    chain.hops[2].caveats = bad
    chain.hops[2].sign(k2)
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 3: increased rate limit (child > parent).
# ---------------------------------------------------------------------------
def test_violation_increased_rate():
    chain, anchor, action, keys, caveats = build_base_chain()
    root, k1, k2, k3 = keys
    bad = replace(caveats[2], rate_limit_per_min=999)  # > parent 60
    chain.hops[2].caveats = bad
    chain.hops[2].sign(k2)
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 4: geofence escape (child circle not inside parent circle).
# ---------------------------------------------------------------------------
def test_violation_geofence_escape():
    chain, anchor, action, keys, caveats = build_base_chain()
    root, k1, k2, k3 = keys
    # Move child circle far away from parent (still valid signature).
    bad = replace(caveats[2], geofence=(48.8566, 2.3522, 50.0))  # Paris
    chain.hops[2].caveats = bad
    chain.hops[2].sign(k2)
    _expect_reject(chain, anchor, action)


def test_violation_geofence_bigger_radius():
    # Child circle centered same but radius exceeds parent -> escape.
    chain, anchor, action, keys, caveats = build_base_chain()
    root, k1, k2, k3 = keys
    bad = replace(caveats[2], geofence=(52.5201, 13.4051, 5000.0))  # bigger than parent 200
    chain.hops[2].caveats = bad
    chain.hops[2].sign(k2)
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 5: wrong child key (parent authorizes key X, next hop uses Y).
# ---------------------------------------------------------------------------
def test_violation_wrong_child_key():
    chain, anchor, action, keys, _ = build_base_chain()
    root, k1, k2, k3 = keys
    # Tamper hop1.child_pub to an unrelated key, re-sign by legit parent k1
    # so signature is valid but the key no longer chains to hop2's parent.
    stranger = mkkey(99)
    chain.hops[1].child_pub = raw_pub(stranger.public_key())
    chain.hops[1].sign(k1)
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 6: tampered payload (body altered after signing).
# ---------------------------------------------------------------------------
def test_violation_tampered_payload():
    chain, anchor, action, _, _ = build_base_chain()
    # Alter a caveat WITHOUT re-signing => signature no longer matches body.
    chain.hops[1].caveats = replace(chain.hops[1].caveats, rate_limit_per_min=61)
    _expect_reject(chain, anchor, action)


def test_violation_tampered_role():
    chain, anchor, action, _, _ = build_base_chain()
    chain.hops[0].role_to = "attacker"  # not re-signed
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# VIOLATION 7: expired action (time after effective valid_until).
# ---------------------------------------------------------------------------
def test_violation_expired_action():
    chain, anchor, _, _, _ = build_base_chain()
    expired = Action(topic="ward3/bed12/vitals/hr",
                     time=1_700_000_000 + 100 * 24 * 3600,  # long after window
                     location=(52.5201, 13.4051), rate_slot=5)
    _expect_reject(chain, anchor, expired)


def test_violation_before_valid_from():
    chain, anchor, _, _, _ = build_base_chain()
    early = Action(topic="ward3/bed12/vitals/hr",
                   time=1_699_000_000,  # before valid_from
                   location=(52.5201, 13.4051), rate_slot=5)
    _expect_reject(chain, anchor, early)


# ---------------------------------------------------------------------------
# VIOLATION 8: action outside caveats (topic / geo / rate).
# ---------------------------------------------------------------------------
def test_violation_action_topic_outside():
    chain, anchor, _, _, _ = build_base_chain()
    a = Action(topic="ward7/other", time=1_700_000_500,
               location=(52.5201, 13.4051), rate_slot=5)
    _expect_reject(chain, anchor, a)


def test_violation_action_geo_outside():
    chain, anchor, _, _, _ = build_base_chain()
    a = Action(topic="ward3/bed12/vitals/hr", time=1_700_000_500,
               location=(48.8566, 2.3522), rate_slot=5)  # Paris
    _expect_reject(chain, anchor, a)


def test_violation_action_rate_outside():
    chain, anchor, _, _, _ = build_base_chain()
    a = Action(topic="ward3/bed12/vitals/hr", time=1_700_000_500,
               location=(52.5201, 13.4051), rate_slot=999)  # exceeds eff 30
    _expect_reject(chain, anchor, a)


# ---------------------------------------------------------------------------
# VIOLATION 9: wrong trust anchor.
# ---------------------------------------------------------------------------
def test_violation_wrong_anchor():
    chain, _, action, _, _ = build_base_chain()
    _expect_reject(chain, raw_pub(mkkey(42).public_key()), action)


# ---------------------------------------------------------------------------
# VIOLATION 10: unknown caveat field on the wire (fail-closed on decode).
# ---------------------------------------------------------------------------
def test_violation_unknown_field_json():
    chain, anchor, action, _, _ = build_base_chain()
    import json
    obj = json.loads(encode_json(chain).decode())
    obj["hops"][1]["caveats"]["evil_field"] = 1
    blob = json.dumps(obj).encode()
    try:
        decode_json(blob)
    except VerificationError:
        return
    raise AssertionError("unknown field not rejected on decode")


def test_violation_unknown_field_cbor():
    chain, anchor, action, _, _ = build_base_chain()
    import cbor2
    obj = cbor2.loads(encode_cbor(chain))
    obj[cg._K_HOPS][1][cg._H_CAV][99] = 1  # bogus caveat int key
    blob = cbor2.dumps(obj)
    try:
        decode_cbor(blob)
    except VerificationError:
        return
    raise AssertionError("unknown cbor field not rejected on decode")


# ---------------------------------------------------------------------------
# Encodings agree: JSON and CBOR decode to a chain that verifies identically.
# ---------------------------------------------------------------------------
def test_encodings_equivalent():
    for depth in (1, 2, 3, 4, 6):
        chain, anchor, action = _demo_chain(depth)
        ej = verify_chain(decode_json(encode_json(chain)), anchor, action)
        ec = verify_chain(decode_cbor(encode_cbor(chain)), anchor, action)
        assert ej.to_dict() == ec.to_dict()


# ---------------------------------------------------------------------------
# Plain-assert runner (no pytest needed).
# ---------------------------------------------------------------------------
def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    failed = []
    for t in tests:
        try:
            t()
            passed += 1
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed.append((t.__name__, repr(e)))
            print(f"FAIL {t.__name__}: {e!r}")
    print(f"\n{passed}/{len(tests)} passed; {len(failed)} failed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    _run_all()
