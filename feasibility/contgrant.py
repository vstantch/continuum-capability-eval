"""contgrant.py -- continuum capability-grant prototype.

Capability tokens for the cloud->fog->gateway->device IoT continuum.

Model (grant@1-style):
  A capability is a CHAIN of delegation HOPS: cloud -> fog -> gateway -> device.
  * The chain is rooted at a trust anchor (root Ed25519 public key).
  * Each hop is signed by the *parent* key over a canonical serialization of
    that hop, and each hop names the child public key it authorizes. So the
    parent's signature simultaneously (a) authenticates the hop body and
    (b) authorizes the named child key for the next hop.
  * Each hop carries a CAVEAT set that is conjunctive, negation-free and
    attenuation-only: a child hop may only narrow, never widen, what the
    parent granted.

Caveats (all attenuation-only, monotone):
  * topic_prefix          -- string prefix; child prefix must extend parent's
  * rate_limit_per_min    -- int; child <= parent
  * geofence              -- (lat, lon, radius_m); child circle inside parent
  * valid_from/valid_until-- unix seconds; child window subset of parent window

Verifier: full-chain verification. Checks, for a presented ACTION
{topic, time, location, rate_slot}:
  1. every hop signature is valid under the parent key (root anchored),
  2. each hop names the next hop's child key (key-chaining),
  3. every caveat attenuates monotonically vs. its parent (no widening),
  4. the action satisfies the *effective* (intersected) caveat set.
FAIL-CLOSED: any unknown caveat field, malformed value, or non-narrowing
caveat causes rejection.

Two wire encodings of the same chain are provided:
  * compact JSON  (encode_json / decode_json)
  * CBOR w/ small integer keys (encode_cbor / decode_cbor)
"""

from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass, field, replace
from typing import Any, Optional

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# --------------------------------------------------------------------------
# Known caveat fields. Anything outside this set => fail-closed reject.
# --------------------------------------------------------------------------
KNOWN_CAVEAT_FIELDS = frozenset(
    {"topic_prefix", "rate_limit_per_min", "geofence", "valid_from", "valid_until"}
)

EARTH_RADIUS_M = 6_371_000.0


class VerificationError(Exception):
    """Raised on any verification failure (fail-closed)."""


# --------------------------------------------------------------------------
# Key helpers
# --------------------------------------------------------------------------
def raw_pub(pk: Ed25519PublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_pub(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


# --------------------------------------------------------------------------
# Geometry: is child circle fully inside parent circle?
# --------------------------------------------------------------------------
def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def circle_inside(child: tuple, parent: tuple) -> bool:
    """child (lat,lon,r) fully contained in parent (lat,lon,R)?

    Contained iff dist(centers) + r_child <= R_parent (great-circle).
    """
    clat, clon, cr = child
    plat, plon, pr = parent
    if cr < 0 or pr < 0:
        return False
    d = _haversine_m(clat, clon, plat, plon)
    return d + cr <= pr + 1e-6


# --------------------------------------------------------------------------
# Caveat set
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Caveats:
    topic_prefix: Optional[str] = None
    rate_limit_per_min: Optional[int] = None
    geofence: Optional[tuple] = None  # (lat, lon, radius_m)
    valid_from: Optional[int] = None  # unix seconds inclusive
    valid_until: Optional[int] = None  # unix seconds inclusive

    def to_dict(self) -> dict:
        d: dict[str, Any] = {}
        if self.topic_prefix is not None:
            d["topic_prefix"] = self.topic_prefix
        if self.rate_limit_per_min is not None:
            d["rate_limit_per_min"] = self.rate_limit_per_min
        if self.geofence is not None:
            d["geofence"] = list(self.geofence)
        if self.valid_from is not None:
            d["valid_from"] = self.valid_from
        if self.valid_until is not None:
            d["valid_until"] = self.valid_until
        return d

    @staticmethod
    def from_dict(d: dict) -> "Caveats":
        # Fail-closed: reject unknown fields here.
        unknown = set(d.keys()) - KNOWN_CAVEAT_FIELDS
        if unknown:
            raise VerificationError(f"unknown caveat field(s): {sorted(unknown)}")
        gf = d.get("geofence")
        if gf is not None:
            gf = tuple(gf)
            if len(gf) != 3:
                raise VerificationError("geofence must be (lat,lon,radius)")
        return Caveats(
            topic_prefix=d.get("topic_prefix"),
            rate_limit_per_min=d.get("rate_limit_per_min"),
            geofence=gf,
            valid_from=d.get("valid_from"),
            valid_until=d.get("valid_until"),
        )


def attenuates(child: Caveats, parent: Caveats) -> bool:
    """True iff `child` only narrows `parent` (monotone attenuation).

    For each dimension: if the parent constrains it, the child must constrain
    it at least as tightly. A child MAY add a constraint the parent lacks
    (that is still narrowing). A child may NOT relax or remove a parent bound.
    """
    # topic_prefix: child must extend parent's prefix.
    if parent.topic_prefix is not None:
        if child.topic_prefix is None:
            return False
        if not child.topic_prefix.startswith(parent.topic_prefix):
            return False

    # rate_limit: child <= parent.
    if parent.rate_limit_per_min is not None:
        if child.rate_limit_per_min is None:
            return False
        if child.rate_limit_per_min > parent.rate_limit_per_min:
            return False

    # geofence: child circle inside parent circle.
    if parent.geofence is not None:
        if child.geofence is None:
            return False
        if not circle_inside(child.geofence, parent.geofence):
            return False

    # valid_from: child window starts no earlier than parent.
    if parent.valid_from is not None:
        if child.valid_from is None or child.valid_from < parent.valid_from:
            return False
    # valid_until: child window ends no later than parent.
    if parent.valid_until is not None:
        if child.valid_until is None or child.valid_until > parent.valid_until:
            return False
    return True


def intersect(a: Caveats, b: Caveats) -> Caveats:
    """Effective (tightest) caveats across two hops. Used to build the
    effective set down the chain; only meaningful when b attenuates a."""
    topic = a.topic_prefix
    if b.topic_prefix is not None and (
        topic is None or len(b.topic_prefix) > len(topic)
    ):
        topic = b.topic_prefix
    rate = min([x for x in (a.rate_limit_per_min, b.rate_limit_per_min) if x is not None], default=None)
    geo = b.geofence if b.geofence is not None else a.geofence
    vf = max([x for x in (a.valid_from, b.valid_from) if x is not None], default=None)
    vu = min([x for x in (a.valid_until, b.valid_until) if x is not None], default=None)
    return Caveats(topic, rate, geo, vf, vu)


# --------------------------------------------------------------------------
# Canonical hop serialization (what gets signed)
# --------------------------------------------------------------------------
@dataclass
class Hop:
    """One delegation hop. Signed by the parent key over canonical bytes."""

    index: int  # 0-based position in chain
    role_from: str  # e.g. "cloud"
    role_to: str  # e.g. "fog"
    parent_pub: bytes  # raw 32-byte parent (signer) public key
    child_pub: bytes  # raw 32-byte child (authorized) public key
    caveats: Caveats
    signature: bytes = b""  # parent signature over canonical_bytes()

    def canonical_obj(self) -> dict:
        """Deterministic dict of the signed body (excludes signature)."""
        return {
            "index": self.index,
            "role_from": self.role_from,
            "role_to": self.role_to,
            "parent_pub": self.parent_pub.hex(),
            "child_pub": self.child_pub.hex(),
            "caveats": self.caveats.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        # Sort keys + compact separators => deterministic canonical form.
        return json.dumps(
            self.canonical_obj(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def sign(self, parent_sk: Ed25519PrivateKey) -> None:
        # Sanity: the signing key must match the declared parent_pub.
        if raw_pub(parent_sk.public_key()) != self.parent_pub:
            raise ValueError("signing key does not match hop.parent_pub")
        self.signature = parent_sk.sign(self.canonical_bytes())


@dataclass
class Chain:
    root_pub: bytes  # trust anchor; must equal hops[0].parent_pub
    hops: list[Hop] = field(default_factory=list)


# --------------------------------------------------------------------------
# Builder
# --------------------------------------------------------------------------
class ChainBuilder:
    """Constructs a signed delegation chain. Purely a convenience helper."""

    def __init__(self, root_sk: Ed25519PrivateKey):
        self.root_sk = root_sk
        self.root_pub = raw_pub(root_sk.public_key())
        self.hops: list[Hop] = []
        self._parent_sk = root_sk
        self._parent_pub = self.root_pub

    def add_hop(
        self,
        role_from: str,
        role_to: str,
        child_sk: Ed25519PrivateKey,
        caveats: Caveats,
    ) -> "ChainBuilder":
        child_pub = raw_pub(child_sk.public_key())
        hop = Hop(
            index=len(self.hops),
            role_from=role_from,
            role_to=role_to,
            parent_pub=self._parent_pub,
            child_pub=child_pub,
            caveats=caveats,
        )
        hop.sign(self._parent_sk)
        self.hops.append(hop)
        # Next hop's parent is this hop's child.
        self._parent_sk = child_sk
        self._parent_pub = child_pub
        return self

    def build(self) -> Chain:
        return Chain(root_pub=self.root_pub, hops=list(self.hops))


# --------------------------------------------------------------------------
# Action to be authorized
# --------------------------------------------------------------------------
@dataclass
class Action:
    topic: str
    time: int  # unix seconds
    location: tuple  # (lat, lon)
    rate_slot: int  # requested messages-in-this-minute count


# --------------------------------------------------------------------------
# Verifier (fail-closed)
# --------------------------------------------------------------------------
def verify_chain(chain: Chain, trust_anchor: bytes, action: Optional[Action] = None) -> Caveats:
    """Verify a full chain against a trust anchor. Optionally check an action.

    Returns the effective (intersected) Caveats on success.
    Raises VerificationError on any failure (fail-closed).
    """
    if not chain.hops:
        raise VerificationError("empty chain")
    if chain.root_pub != trust_anchor:
        raise VerificationError("chain root does not match trust anchor")

    expected_parent = trust_anchor
    effective: Optional[Caveats] = None
    prev_caveats: Optional[Caveats] = None

    for i, hop in enumerate(chain.hops):
        # 0. structural: index continuity.
        if hop.index != i:
            raise VerificationError(f"hop {i}: bad index {hop.index}")
        # 1. key chaining: this hop must be signed by the expected parent.
        if hop.parent_pub != expected_parent:
            raise VerificationError(f"hop {i}: parent key does not chain")
        # 2. signature: parent signs canonical body.
        try:
            load_pub(hop.parent_pub).verify(hop.signature, hop.canonical_bytes())
        except InvalidSignature:
            raise VerificationError(f"hop {i}: invalid signature")
        # 3. attenuation: caveats must narrow vs. previous hop (fail-closed
        #    also rejects unknown fields via Caveats.from_dict on decode).
        if prev_caveats is not None and not attenuates(hop.caveats, prev_caveats):
            raise VerificationError(f"hop {i}: caveats do not attenuate (widening)")
        # 4. accumulate effective caveats.
        effective = hop.caveats if effective is None else intersect(effective, hop.caveats)
        prev_caveats = hop.caveats
        expected_parent = hop.child_pub

    assert effective is not None
    if action is not None:
        check_action(effective, action)
    return effective


def check_action(eff: Caveats, action: Action) -> None:
    """Fail-closed: action must satisfy every effective caveat."""
    if eff.topic_prefix is not None and not action.topic.startswith(eff.topic_prefix):
        raise VerificationError("action topic outside topic_prefix")
    if eff.rate_limit_per_min is not None and action.rate_slot > eff.rate_limit_per_min:
        raise VerificationError("action rate exceeds rate_limit_per_min")
    if eff.valid_from is not None and action.time < eff.valid_from:
        raise VerificationError("action time before valid_from")
    if eff.valid_until is not None and action.time > eff.valid_until:
        raise VerificationError("action time after valid_until (expired)")
    if eff.geofence is not None:
        glat, glon, gr = eff.geofence
        d = _haversine_m(action.location[0], action.location[1], glat, glon)
        if d > gr + 1e-6:
            raise VerificationError("action location outside geofence")


# --------------------------------------------------------------------------
# Wire encoding (a): compact JSON
# --------------------------------------------------------------------------
def encode_json(chain: Chain) -> bytes:
    obj = {
        "root_pub": chain.root_pub.hex(),
        "hops": [
            {**hop.canonical_obj(), "sig": hop.signature.hex()} for hop in chain.hops
        ],
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def decode_json(blob: bytes) -> Chain:
    obj = json.loads(blob.decode("utf-8"))
    root_pub = bytes.fromhex(obj["root_pub"])
    hops = []
    for h in obj["hops"]:
        # Fail-closed on unknown top-level hop keys.
        allowed = {"index", "role_from", "role_to", "parent_pub", "child_pub", "caveats", "sig"}
        unknown = set(h.keys()) - allowed
        if unknown:
            raise VerificationError(f"unknown hop field(s): {sorted(unknown)}")
        hops.append(
            Hop(
                index=h["index"],
                role_from=h["role_from"],
                role_to=h["role_to"],
                parent_pub=bytes.fromhex(h["parent_pub"]),
                child_pub=bytes.fromhex(h["child_pub"]),
                caveats=Caveats.from_dict(h["caveats"]),
                signature=bytes.fromhex(h["sig"]),
            )
        )
    return Chain(root_pub=root_pub, hops=hops)


# --------------------------------------------------------------------------
# Wire encoding (b): CBOR with small integer keys
# --------------------------------------------------------------------------
# Integer key maps (compact wire form).
_K_ROOT = 0
_K_HOPS = 1
_H_INDEX = 0
_H_RF = 1
_H_RT = 2
_H_PP = 3
_H_CP = 4
_H_CAV = 5
_H_SIG = 6
_C_TOPIC = 0
_C_RATE = 1
_C_GEO = 2
_C_VF = 3
_C_VU = 4

_C_FIELD_BY_INT = {
    _C_TOPIC: "topic_prefix",
    _C_RATE: "rate_limit_per_min",
    _C_GEO: "geofence",
    _C_VF: "valid_from",
    _C_VU: "valid_until",
}
_C_INT_BY_FIELD = {v: k for k, v in _C_FIELD_BY_INT.items()}


def _caveats_to_cbor(c: Caveats) -> dict:
    d: dict[int, Any] = {}
    if c.topic_prefix is not None:
        d[_C_TOPIC] = c.topic_prefix
    if c.rate_limit_per_min is not None:
        d[_C_RATE] = c.rate_limit_per_min
    if c.geofence is not None:
        d[_C_GEO] = list(c.geofence)
    if c.valid_from is not None:
        d[_C_VF] = c.valid_from
    if c.valid_until is not None:
        d[_C_VU] = c.valid_until
    return d


def _caveats_from_cbor(d: dict) -> Caveats:
    unknown = set(d.keys()) - set(_C_FIELD_BY_INT.keys())
    if unknown:
        raise VerificationError(f"unknown cbor caveat key(s): {sorted(unknown)}")
    gf = d.get(_C_GEO)
    if gf is not None:
        gf = tuple(gf)
        if len(gf) != 3:
            raise VerificationError("geofence must be (lat,lon,radius)")
    return Caveats(
        topic_prefix=d.get(_C_TOPIC),
        rate_limit_per_min=d.get(_C_RATE),
        geofence=gf,
        valid_from=d.get(_C_VF),
        valid_until=d.get(_C_VU),
    )


def encode_cbor(chain: Chain) -> bytes:
    obj = {
        _K_ROOT: chain.root_pub,  # raw bytes, not hex
        _K_HOPS: [
            {
                _H_INDEX: hop.index,
                _H_RF: hop.role_from,
                _H_RT: hop.role_to,
                _H_PP: hop.parent_pub,
                _H_CP: hop.child_pub,
                _H_CAV: _caveats_to_cbor(hop.caveats),
                _H_SIG: hop.signature,
            }
            for hop in chain.hops
        ],
    }
    return cbor2.dumps(obj, canonical=True)


def decode_cbor(blob: bytes) -> Chain:
    obj = cbor2.loads(blob)
    root_pub = obj[_K_ROOT]
    hops = []
    for h in obj[_K_HOPS]:
        allowed = {_H_INDEX, _H_RF, _H_RT, _H_PP, _H_CP, _H_CAV, _H_SIG}
        unknown = set(h.keys()) - allowed
        if unknown:
            raise VerificationError(f"unknown cbor hop key(s): {sorted(unknown)}")
        hops.append(
            Hop(
                index=h[_H_INDEX],
                role_from=h[_H_RF],
                role_to=h[_H_RT],
                parent_pub=h[_H_PP],
                child_pub=h[_H_CP],
                caveats=_caveats_from_cbor(h[_H_CAV]),
                signature=h[_H_SIG],
            )
        )
    return Chain(root_pub=root_pub, hops=hops)


# --------------------------------------------------------------------------
# Demo / self-check when run directly.
# --------------------------------------------------------------------------
def _demo_chain(depth: int, seed_offset: int = 0):
    """Build a realistic IoMT demo chain of given depth (>=1).

    Roles cycle cloud->fog->gateway->device then repeat for deeper chains.
    Returns (chain, trust_anchor, sample_action).
    """
    import os

    roles = ["cloud", "fog", "gateway", "device", "sensor", "actuator"]
    # Deterministic keys from seeded raw bytes.
    def mkkey(i: int) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            bytes((i * 7 + seed_offset + j) % 256 for j in range(32))
        )

    root_sk = mkkey(0)
    b = ChainBuilder(root_sk)
    # Root/base caveats: broad, then attenuate.
    base = Caveats(
        topic_prefix="ward3/",
        rate_limit_per_min=120,
        geofence=(52.5200, 13.4050, 500.0),  # hospital campus, 500 m
        valid_from=1_700_000_000,
        valid_until=1_700_000_000 + 7 * 24 * 3600,
    )
    caveat_ladder = [
        base,
        replace(base, topic_prefix="ward3/bed12/", rate_limit_per_min=60,
                geofence=(52.5200, 13.4050, 200.0)),
        replace(base, topic_prefix="ward3/bed12/vitals/", rate_limit_per_min=30,
                geofence=(52.5201, 13.4051, 80.0),
                valid_until=1_700_000_000 + 2 * 24 * 3600),
        replace(base, topic_prefix="ward3/bed12/vitals/hr", rate_limit_per_min=12,
                geofence=(52.5201, 13.4051, 30.0),
                valid_until=1_700_000_000 + 24 * 3600),
        replace(base, topic_prefix="ward3/bed12/vitals/hr", rate_limit_per_min=6,
                geofence=(52.5201, 13.4051, 15.0),
                valid_until=1_700_000_000 + 12 * 3600),
        replace(base, topic_prefix="ward3/bed12/vitals/hr", rate_limit_per_min=4,
                geofence=(52.5201, 13.4051, 10.0),
                valid_until=1_700_000_000 + 6 * 3600),
    ]
    for i in range(depth):
        child = mkkey(i + 1)
        rf = roles[i % len(roles)]
        rt = roles[(i + 1) % len(roles)]
        cav = caveat_ladder[min(i, len(caveat_ladder) - 1)]
        b.add_hop(rf, rt, child, cav)
    chain = b.build()
    eff = verify_chain(chain, chain.root_pub)
    action = Action(
        topic="ward3/bed12/vitals/hr" if depth >= 4 else (eff.topic_prefix + "x"),
        time=1_700_000_500,
        location=(52.5201, 13.4051),
        rate_slot=min(eff.rate_limit_per_min, 3),
    )
    return chain, chain.root_pub, action


if __name__ == "__main__":
    print("contgrant self-check")
    for depth in (1, 2, 3, 4, 6):
        chain, anchor, action = _demo_chain(depth)
        eff = verify_chain(chain, anchor, action)
        j = encode_json(chain)
        c = encode_cbor(chain)
        # Round-trip both encodings and re-verify.
        assert verify_chain(decode_json(j), anchor, action)
        assert verify_chain(decode_cbor(c), anchor, action)
        ratio = len(c) / len(j)
        print(
            f"  depth={depth}: JSON={len(j):5d}B  CBOR={len(c):5d}B  "
            f"CBOR/JSON={ratio:.3f}  eff.topic={eff.topic_prefix!r}"
        )
    print("OK")
