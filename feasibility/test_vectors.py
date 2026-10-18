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
# WIRE ROBUSTNESS (added for v1.1): malformed input, duplicate keys,
# non-canonical CBOR, type confusion, out-of-range integers, Unicode
# normalization, signature malleability. Each must end in VerificationError,
# never in another exception and never in acceptance.
# ---------------------------------------------------------------------------
def _expect_decode_reject(decode, blob):
    try:
        decode(blob)
    except VerificationError:
        return
    raise AssertionError("expected VerificationError on decode")


def test_wire_truncated_inputs():
    chain, _, _, _, _ = build_base_chain()
    j, c = encode_json(chain), encode_cbor(chain)
    for n in (1, 5, len(j) // 2):
        _expect_decode_reject(decode_json, j[:-n])
    for n in (1, 5, len(c) // 2):
        _expect_decode_reject(decode_cbor, c[:-n])
    _expect_decode_reject(decode_json, b"\xff\xfe")
    _expect_decode_reject(decode_cbor, b"")


def test_wire_duplicate_json_key():
    chain, _, _, _, _ = build_base_chain()
    s = encode_json(chain).decode()
    dup = s.replace('"caveats":{', '"caveats":{"topic_prefix":"x/",', 1)
    _expect_decode_reject(decode_json, dup.encode())


def test_wire_noncanonical_cbor():
    import cbor2
    chain, _, _, _, _ = build_base_chain()
    c = encode_cbor(chain)
    _expect_decode_reject(decode_cbor, c + b"\x00")  # trailing bytes
    obj = cbor2.loads(c)
    # Reverse the top-level key order: same content, non-canonical bytes.
    swapped = cbor2.dumps({cg._K_HOPS: obj[cg._K_HOPS], cg._K_ROOT: obj[cg._K_ROOT]})
    assert swapped != c
    _expect_decode_reject(decode_cbor, swapped)


def test_wire_type_confusion():
    import json
    chain, _, _, _, _ = build_base_chain()
    base = json.loads(encode_json(chain).decode())
    bad_values = [
        ("rate_limit_per_min", "120"),
        ("rate_limit_per_min", True),
        ("rate_limit_per_min", 2**40),  # beyond the 32-bit bound
        ("rate_limit_per_min", -1),
        ("valid_until", 2**70),  # beyond the 64-bit bound
        ("valid_until", 1.5),
        ("geofence", [52.52, 13.405]),
        ("geofence", [52.52, 13.405, "500"]),
        ("geofence", [95.0, 13.405, 500.0]),
        ("topic_prefix", 7),
    ]
    for field_name, v in bad_values:
        obj = copy.deepcopy(base)
        obj["hops"][1]["caveats"][field_name] = v
        _expect_decode_reject(decode_json, json.dumps(obj).encode())


def test_wire_unicode_not_nfc():
    # "e" + combining acute (NFD) is rejected; an NFC topic is accepted.
    root, k1 = mkkey(0), mkkey(1)
    for topic, ok in (("ward3/café/", True), ("ward3/café/", False)):
        chain = ChainBuilder(root).add_hop("cloud", "fog", k1, Caveats(topic_prefix=topic)).build()
        try:
            decode_json(encode_json(chain))
            accepted = True
        except VerificationError:
            accepted = False
        assert accepted == ok, topic


def test_wire_signature_malleability():
    # S + L is the same signature in a non-canonical form; it must not verify.
    L = 2**252 + 27742317777372353535851937790883648493
    chain, anchor, action, _, _ = build_base_chain()
    sig = chain.hops[0].signature
    s = int.from_bytes(sig[32:], "little")
    chain.hops[0].signature = sig[:32] + (s + L).to_bytes(32, "little")
    _expect_reject(chain, anchor, action)


# ---------------------------------------------------------------------------
# REQUESTS (added for v1.1): proof of possession, replay, rate counted by the
# verifier, clock skew, restart warm-up, revocation epochs, evidence chain.
# ---------------------------------------------------------------------------
T0 = 1_700_000_500
HERE_LOC = (52.5201, 13.4051)


def _request_setup():
    chain, anchor, _, keys, _ = build_base_chain()
    leaf = keys[3]
    rv = cg.RequestVerifier(anchor, boot_time=T0 - 3600)
    return chain, anchor, leaf, rv, keys


def _req(chain, leaf, ctr, ts, topic="ward3/bed12/vitals/hr"):
    import hashlib
    r = cg.Request(cg.chain_digest(chain), topic, hashlib.sha256(b"hr=72").digest(), ctr, ts)
    return r, cg.sign_request(leaf, r)


def _expect_request_reject(rv, chain, r, sig, now, loc=HERE_LOC):
    try:
        rv.verify(chain, r, sig, now, loc)
    except VerificationError:
        return
    raise AssertionError("expected request rejection")


def test_request_accept_and_pop():
    chain, _, leaf, rv, keys = _request_setup()
    r, sig = _req(chain, leaf, 1, T0)
    assert rv.verify(chain, r, sig, T0, HERE_LOC)
    # Signed by the gateway key instead of the leaf: no proof of possession.
    r2, sig2 = _req(chain, keys[2], 2, T0)
    _expect_request_reject(rv, chain, r2, sig2, T0)
    # Request bound to another chain digest.
    r3 = replace(r, counter=3, chain_digest=b"\x00" * 32)
    _expect_request_reject(rv, chain, r3, cg.sign_request(leaf, r3), T0)


def test_request_replay_and_skew():
    chain, _, leaf, rv, _ = _request_setup()
    r, sig = _req(chain, leaf, 7, T0)
    rv.verify(chain, r, sig, T0, HERE_LOC)
    _expect_request_reject(rv, chain, r, sig, T0 + 1)  # exact replay
    r_old, s_old = _req(chain, leaf, 6, T0 + 1)
    _expect_request_reject(rv, chain, r_old, s_old, T0 + 1)  # lower counter
    r_late, s_late = _req(chain, leaf, 8, T0 - 31)
    _expect_request_reject(rv, chain, r_late, s_late, T0)  # outside 30 s skew


def test_request_rate_counted_by_verifier():
    # Effective limit is 30/min (hop 2). The 31st request in one minute is
    # refused; once the window slides, requests are accepted again.
    chain, _, leaf, rv, _ = _request_setup()
    for i in range(30):
        r, s = _req(chain, leaf, i + 1, T0 + i)
        rv.verify(chain, r, s, T0 + i, HERE_LOC)
    r, s = _req(chain, leaf, 31, T0 + 30)
    _expect_request_reject(rv, chain, r, s, T0 + 30)
    r, s = _req(chain, leaf, 32, T0 + 61)
    assert rv.verify(chain, r, s, T0 + 61, HERE_LOC)


def test_request_restart_warmup():
    chain, anchor, leaf, _, _ = _request_setup()
    rv = cg.RequestVerifier(anchor, boot_time=T0)
    r, s = _req(chain, leaf, 1, T0 + 10)
    _expect_request_reject(rv, chain, r, s, T0 + 10)  # inside warm-up
    r, s = _req(chain, leaf, 2, T0 + 60)
    assert rv.verify(chain, r, s, T0 + 60, HERE_LOC)


def test_request_revoked_by_epoch():
    chain, anchor, leaf, rv, keys = _request_setup()
    r, s = _req(chain, leaf, 1, T0)
    rv.verify(chain, r, s, T0, HERE_LOC)
    # An epoch not signed by the root is refused.
    try:
        rv.install_epoch(cg.sign_epoch(keys[1], 1, {cg.hop_id(chain.hops[1])}))
        raise AssertionError("epoch from non-root key accepted")
    except VerificationError:
        pass
    rv.install_epoch(cg.sign_epoch(keys[0], 1, {cg.hop_id(chain.hops[1])}))
    r, s = _req(chain, leaf, 2, T0 + 1)
    _expect_request_reject(rv, chain, r, s, T0 + 1)


def test_evidence_chain_detects_tampering():
    chain, anchor, leaf, _, keys = _request_setup()
    log = cg.EvidenceLog(keys[1])  # fog writer key
    rv = cg.RequestVerifier(anchor, boot_time=T0 - 3600, evidence=log)
    for i in range(4):
        r, s = _req(chain, leaf, i + 1, T0 + i)
        rv.decide(chain, r, s, T0 + i, HERE_LOC)
    r, s = _req(chain, leaf, 4, T0 + 5)  # replayed counter -> deny, recorded
    assert not rv.decide(chain, r, s, T0 + 5, HERE_LOC)
    anchored = log.anchor()
    assert cg.verify_evidence(log.records, log.writer_pub, (anchored,)) == anchored[1]
    # Modifying an anchored record breaks the chain.
    edited = copy.deepcopy(log.records)
    edited[2]["body"]["verdict"] = "deny"
    try:
        cg.verify_evidence(edited, log.writer_pub, (anchored,))
        raise AssertionError("edited record not detected")
    except VerificationError:
        pass
    # Deleting an internal record leaves a sequence gap.
    try:
        cg.verify_evidence(log.records[:1] + log.records[2:], log.writer_pub)
        raise AssertionError("deleted record not detected")
    except VerificationError:
        pass
    # Truncating an anchored tail fails the anchor check; truncating an
    # unanchored tail does not (documented limit of hash chaining).
    try:
        cg.verify_evidence(log.records[:-1], log.writer_pub, (anchored,))
        raise AssertionError("truncated anchored tail not detected")
    except VerificationError:
        pass
    cg.verify_evidence(log.records[:-1], log.writer_pub)


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
