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

import hashlib
import json
import math
import struct
import unicodedata
from collections import deque
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
        if not isinstance(d, dict):
            raise VerificationError("caveats must be a map")
        unknown = set(d.keys()) - KNOWN_CAVEAT_FIELDS
        if unknown:
            raise VerificationError(f"unknown caveat field(s): {sorted(unknown)}")
        gf = d.get("geofence")
        if gf is not None:
            if not isinstance(gf, (list, tuple)):
                raise VerificationError("geofence must be (lat,lon,radius)")
            gf = tuple(gf)
            if len(gf) != 3:
                raise VerificationError("geofence must be (lat,lon,radius)")
        c = Caveats(
            topic_prefix=d.get("topic_prefix"),
            rate_limit_per_min=d.get("rate_limit_per_min"),
            geofence=gf,
            valid_from=d.get("valid_from"),
            valid_until=d.get("valid_until"),
        )
        _check_caveat_types(c)
        return c


# Integer caveats are bounded so that a verifier with fixed-width integers
# (the planned no_std verifier) reaches the same verdict as this one.
MAX_RATE = 2**32 - 1
MAX_TIME = 2**63 - 1


def _is_int(v: Any) -> bool:
    # bool is a subclass of int in Python; a wire "true" is not a number.
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v: Any) -> bool:
    return (_is_int(v) or isinstance(v, float)) and math.isfinite(v)


def _check_text(s: Any, what: str) -> None:
    # Text is compared code point by code point, so a verifier must not see
    # two spellings of one string: only NFC-normalized text is accepted.
    if not isinstance(s, str):
        raise VerificationError(f"{what} must be text")
    if not unicodedata.is_normalized("NFC", s):
        raise VerificationError(f"{what} is not NFC-normalized")


def _check_caveat_types(c: Caveats) -> None:
    """Fail-closed type and range checks on decoded caveats."""
    if c.topic_prefix is not None:
        _check_text(c.topic_prefix, "topic_prefix")
    if c.rate_limit_per_min is not None:
        if not _is_int(c.rate_limit_per_min) or not 0 <= c.rate_limit_per_min <= MAX_RATE:
            raise VerificationError("rate_limit_per_min out of range")
    if c.geofence is not None:
        if not all(_is_num(v) for v in c.geofence):
            raise VerificationError("geofence values must be finite numbers")
        lat, lon, r = c.geofence
        if not (-90 <= lat <= 90 and -180 <= lon <= 180 and r >= 0):
            raise VerificationError("geofence out of range")
    for name in ("valid_from", "valid_until"):
        v = getattr(c, name)
        if v is not None and (not _is_int(v) or not 0 <= v <= MAX_TIME):
            raise VerificationError(f"{name} out of range")


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


def _no_duplicate_keys(pairs: list) -> dict:
    # A JSON object with a repeated key means different things to parsers
    # that keep the first or the last value; reject it outright.
    d = {}
    for k, v in pairs:
        if k in d:
            raise VerificationError(f"duplicate JSON key: {k!r}")
        d[k] = v
    return d


def _check_hop(hop: Hop) -> Hop:
    """Fail-closed type checks on a decoded hop (caveats are checked on
    construction)."""
    if not _is_int(hop.index) or hop.index < 0:
        raise VerificationError("hop index must be a non-negative integer")
    _check_text(hop.role_from, "role_from")
    _check_text(hop.role_to, "role_to")
    for name in ("parent_pub", "child_pub"):
        v = getattr(hop, name)
        if not isinstance(v, bytes) or len(v) != 32:
            raise VerificationError(f"{name} must be 32 bytes")
    if not isinstance(hop.signature, bytes) or len(hop.signature) != 64:
        raise VerificationError("signature must be 64 bytes")
    return hop


def _hex32(v: Any, n: int) -> bytes:
    if not isinstance(v, str) or len(v) != 2 * n:
        raise VerificationError("bad hex field")
    return bytes.fromhex(v)


def decode_json(blob: bytes) -> Chain:
    # Any parse or shape error becomes a VerificationError, so the caller
    # sees one fail-closed outcome whatever the input.
    try:
        return _decode_json(blob)
    except VerificationError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise VerificationError(f"malformed JSON chain: {type(e).__name__}") from e


def _decode_json(blob: bytes) -> Chain:
    obj = json.loads(blob.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if set(obj.keys()) != {"root_pub", "hops"}:
        raise VerificationError("chain must have exactly root_pub and hops")
    root_pub = _hex32(obj["root_pub"], 32)
    hops = []
    for h in obj["hops"]:
        # Fail-closed on unknown top-level hop keys.
        allowed = {"index", "role_from", "role_to", "parent_pub", "child_pub", "caveats", "sig"}
        unknown = set(h.keys()) - allowed
        if unknown:
            raise VerificationError(f"unknown hop field(s): {sorted(unknown)}")
        hops.append(
            _check_hop(
                Hop(
                    index=h["index"],
                    role_from=h["role_from"],
                    role_to=h["role_to"],
                    parent_pub=_hex32(h["parent_pub"], 32),
                    child_pub=_hex32(h["child_pub"], 32),
                    caveats=Caveats.from_dict(h["caveats"]),
                    signature=_hex32(h["sig"], 64),
                )
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
    if not isinstance(d, dict):
        raise VerificationError("caveats must be a map")
    unknown = set(d.keys()) - set(_C_FIELD_BY_INT.keys())
    if unknown:
        raise VerificationError(f"unknown cbor caveat key(s): {sorted(unknown)}")
    gf = d.get(_C_GEO)
    if gf is not None:
        if not isinstance(gf, (list, tuple)):
            raise VerificationError("geofence must be (lat,lon,radius)")
        gf = tuple(gf)
        if len(gf) != 3:
            raise VerificationError("geofence must be (lat,lon,radius)")
    c = Caveats(
        topic_prefix=d.get(_C_TOPIC),
        rate_limit_per_min=d.get(_C_RATE),
        geofence=gf,
        valid_from=d.get(_C_VF),
        valid_until=d.get(_C_VU),
    )
    _check_caveat_types(c)
    return c


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
    try:
        return _decode_cbor(blob)
    except VerificationError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, cbor2.CBORDecodeError) as e:
        raise VerificationError(f"malformed CBOR chain: {type(e).__name__}") from e


def _decode_cbor(blob: bytes) -> Chain:
    obj = cbor2.loads(blob)
    # Accept only the canonical encoding: re-encoding must reproduce the input
    # byte for byte. This rejects trailing bytes, duplicate map keys (they
    # collapse on decode), indefinite lengths, and non-minimal integers.
    if cbor2.dumps(obj, canonical=True) != blob:
        raise VerificationError("non-canonical CBOR encoding")
    if not isinstance(obj, dict) or set(obj.keys()) != {_K_ROOT, _K_HOPS}:
        raise VerificationError("chain must have exactly root and hops")
    root_pub = obj[_K_ROOT]
    if not isinstance(root_pub, bytes) or len(root_pub) != 32:
        raise VerificationError("root_pub must be 32 bytes")
    hops = []
    for h in obj[_K_HOPS]:
        allowed = {_H_INDEX, _H_RF, _H_RT, _H_PP, _H_CP, _H_CAV, _H_SIG}
        unknown = set(h.keys()) - allowed
        if unknown:
            raise VerificationError(f"unknown cbor hop key(s): {sorted(unknown)}")
        hops.append(
            _check_hop(
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
        )
    return Chain(root_pub=root_pub, hops=hops)


# --------------------------------------------------------------------------
# Request handling: revocation epochs, proof of possession, replay, rate.
#
# verify_chain() establishes that a chain is a valid delegation. A request
# additionally needs (a) proof that the requester holds the leaf private
# key, (b) freshness, so that a captured request cannot be replayed, and
# (c) a rate count kept by the verifier, not claimed by the requester. The
# verifier's own clock and location source supply time and place; the
# requester's timestamp is only checked against them.
# --------------------------------------------------------------------------
REQUEST_DOMAIN = b"contgrant-request-v1\x00"
EPOCH_DOMAIN = b"contgrant-epoch-v1\x00"
EVIDENCE_DOMAIN = b"contgrant-evidence-v1\x00"


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hop_id(hop: Hop) -> bytes:
    """Stable identifier of a signed hop; revoking it revokes every chain
    that contains it."""
    return hashlib.sha256(hop.canonical_bytes() + hop.signature).digest()


def chain_digest(chain: Chain) -> bytes:
    """Encoding-independent digest of a chain (JSON and CBOR agree)."""
    h = hashlib.sha256(chain.root_pub)
    for hop in chain.hops:
        body = hop.canonical_bytes()
        h.update(struct.pack(">I", len(body)) + body + hop.signature)
    return h.digest()


@dataclass(frozen=True)
class RevocationEpoch:
    """Signed revocation digest for one epoch, issued by the root."""

    epoch_id: int
    revoked: frozenset  # of hop_id() values
    signature: bytes = b""

    def signing_bytes(self) -> bytes:
        body = {"epoch": self.epoch_id, "revoked": sorted(r.hex() for r in self.revoked)}
        return EPOCH_DOMAIN + _canon(body)


def sign_epoch(root_sk: Ed25519PrivateKey, epoch_id: int, revoked: set) -> RevocationEpoch:
    e = RevocationEpoch(epoch_id, frozenset(revoked))
    return replace(e, signature=root_sk.sign(e.signing_bytes()))


@dataclass(frozen=True)
class Request:
    chain_digest: bytes  # binds the request to one presented chain
    topic: str
    payload_digest: bytes  # SHA-256 of the message the request carries
    counter: int  # strictly increasing per leaf key
    timestamp: int  # requester clock, unix seconds

    def signing_bytes(self) -> bytes:
        body = {
            "chain": self.chain_digest.hex(),
            "topic": self.topic,
            "payload": self.payload_digest.hex(),
            "ctr": self.counter,
            "ts": self.timestamp,
        }
        return REQUEST_DOMAIN + _canon(body)


def sign_request(leaf_sk: Ed25519PrivateKey, req: Request) -> bytes:
    return leaf_sk.sign(req.signing_bytes())


class RequestVerifier:
    """Stateful request check at one verifier.

    State is kept per leaf key: the highest accepted counter (replay) and the
    times of exercises accepted in the last window (rate). Both live in memory.
    After a restart the verifier refuses every request for a warm-up period of
    max(window, 2 * max_skew): any request accepted afterwards carries a
    timestamp later than the restart, so pre-restart requests cannot be
    replayed, and no pre-restart exercise still counts toward the rate window,
    so a reboot cannot reset the rate budget. Each verifier counts on its own;
    a leaf served by k verifiers can reach k times its rate.
    """

    def __init__(
        self,
        trust_anchor: bytes,
        boot_time: int,
        max_skew_s: int = 30,
        window_s: int = 60,
        evidence: Optional["EvidenceLog"] = None,
    ):
        self.anchor = trust_anchor
        self.max_skew_s = max_skew_s
        self.window_s = window_s
        self.warmup_until = boot_time + max(window_s, 2 * max_skew_s)
        self.epoch: Optional[RevocationEpoch] = None
        self.evidence = evidence
        self._high: dict[bytes, int] = {}
        self._recent: dict[bytes, deque] = {}

    def install_epoch(self, epoch: RevocationEpoch) -> None:
        try:
            load_pub(self.anchor).verify(epoch.signature, epoch.signing_bytes())
        except InvalidSignature:
            raise VerificationError("epoch digest not signed by root")
        if self.epoch is not None and epoch.epoch_id <= self.epoch.epoch_id:
            raise VerificationError("epoch is not newer than the installed one")
        self.epoch = epoch

    def verify(self, chain: Chain, req: Request, sig: bytes, now: int, location: tuple) -> Caveats:
        """Return the effective caveats if the request is allowed; raise
        VerificationError otherwise. `now` and `location` come from the
        verifier's own clock and location source."""
        if now < self.warmup_until:
            raise VerificationError("verifier in warm-up after restart")
        eff = verify_chain(chain, self.anchor)
        if self.epoch is not None and any(hop_id(h) in self.epoch.revoked for h in chain.hops):
            raise VerificationError("chain contains a revoked hop")
        if req.chain_digest != chain_digest(chain):
            raise VerificationError("request bound to a different chain")
        _check_text(req.topic, "request topic")
        if not (_is_int(req.counter) and _is_int(req.timestamp)):
            raise VerificationError("request counter/timestamp must be integers")
        leaf = chain.hops[-1].child_pub
        try:
            load_pub(leaf).verify(sig, req.signing_bytes())
        except InvalidSignature:
            raise VerificationError("no proof of possession of the leaf key")
        if abs(now - req.timestamp) > self.max_skew_s:
            raise VerificationError("request timestamp outside clock-skew bound")
        if req.counter <= self._high.get(leaf, -1):
            raise VerificationError("replayed or reordered request")
        # A fresh, authenticated request is consumed whatever the verdict
        # below, so the same signed request is never evaluated twice.
        self._high[leaf] = req.counter
        recent = self._recent.setdefault(leaf, deque())
        while recent and recent[0] <= now - self.window_s:
            recent.popleft()
        check_action(eff, Action(topic=req.topic, time=now, location=location,
                                 rate_slot=len(recent) + 1))
        recent.append(now)
        return eff

    def decide(self, chain: Chain, req: Request, sig: bytes, now: int, location: tuple) -> bool:
        """verify() plus one evidence record per decision, allow or deny."""
        try:
            self.verify(chain, req, sig, now, location)
            verdict, reason = "allow", ""
        except VerificationError as e:
            verdict, reason = "deny", str(e)
        if self.evidence is not None:
            self.evidence.append({
                "verdict": verdict,
                "reason": reason,
                "chain": chain_digest(chain).hex(),
                "leaf": chain.hops[-1].child_pub.hex() if chain.hops else "",
                "ctr": req.counter,
                "topic": req.topic,
                "payload": req.payload_digest.hex(),
                "time": now,
                "epoch": self.epoch.epoch_id if self.epoch is not None else -1,
            })
        return verdict == "allow"


# --------------------------------------------------------------------------
# Evidence: per-verifier hash-chained, signed decision records.
# --------------------------------------------------------------------------
GENESIS = b"\x00" * 32


class EvidenceLog:
    """Append-only decision log. Record n carries seq=n and the hash of
    record n-1; each record is signed by the writer key. Anchoring sends
    (seq, head) upstream; the anchor fixes every record up to seq."""

    def __init__(self, writer_sk: Ed25519PrivateKey):
        self._sk = writer_sk
        self.writer_pub = raw_pub(writer_sk.public_key())
        self.records: list[dict] = []
        self.head = GENESIS

    def append(self, decision: dict) -> dict:
        body = {"seq": len(self.records), "prev": self.head.hex(), **decision}
        raw = _canon(body)
        rec = {"body": body, "sig": self._sk.sign(EVIDENCE_DOMAIN + raw).hex()}
        self.records.append(rec)
        self.head = hashlib.sha256(raw).digest()
        return rec

    def anchor(self) -> tuple[int, bytes]:
        return len(self.records) - 1, self.head


def verify_evidence(records: list[dict], writer_pub: bytes,
                    anchors: tuple = ()) -> bytes:
    """Check a log from genesis: sequence, hash links, signatures, and that
    it re-derives every upstream anchor (seq, head). Returns the head."""
    pk = load_pub(writer_pub)
    head = GENESIS
    want = dict(anchors)
    for i, rec in enumerate(records):
        body = rec["body"]
        if body.get("seq") != i:
            raise VerificationError(f"evidence: sequence gap at {i}")
        if body.get("prev") != head.hex():
            raise VerificationError(f"evidence: broken hash link at {i}")
        raw = _canon(body)
        try:
            pk.verify(bytes.fromhex(rec["sig"]), EVIDENCE_DOMAIN + raw)
        except InvalidSignature:
            raise VerificationError(f"evidence: bad signature at {i}")
        head = hashlib.sha256(raw).digest()
        if i in want and want.pop(i) != head:
            raise VerificationError(f"evidence: anchor mismatch at {i}")
    if want:
        raise VerificationError(f"evidence: anchored records missing: {sorted(want)}")
    return head


# --------------------------------------------------------------------------
# Demo / self-check when run directly.
# --------------------------------------------------------------------------
def _demo_key(i: int, seed_offset: int = 0) -> Ed25519PrivateKey:
    """Deterministic demo key i (0 = root) from seeded raw bytes."""
    return Ed25519PrivateKey.from_private_bytes(
        bytes((i * 7 + seed_offset + j) % 256 for j in range(32))
    )


def _demo_chain(depth: int, seed_offset: int = 0):
    """Build a realistic IoMT demo chain of given depth (>=1).

    Roles cycle cloud->fog->gateway->device then repeat for deeper chains.
    Returns (chain, trust_anchor, sample_action).
    """
    import os

    roles = ["cloud", "fog", "gateway", "device", "sensor", "actuator"]
    def mkkey(i: int) -> Ed25519PrivateKey:
        return _demo_key(i, seed_offset)

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
