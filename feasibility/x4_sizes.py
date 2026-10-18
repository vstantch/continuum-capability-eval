"""x4_sizes.py -- token size vs. chain depth vs. transport MTU budgets.

Measures serialized capability-chain size (compact JSON and CBOR) at depths
1,2,3,4,6 using a realistic IoMT caveat set, then produces a fits/doesn't-fit
matrix against a set of transport budgets.

Outputs:
  data/x4_sizes.csv        -- depth, encoding, size_bytes
  data/x4_fit_matrix.csv   -- depth x transport, encoding, fits(bool)
"""

from __future__ import annotations

import csv
import os

from contgrant import _demo_chain, encode_json, encode_cbor, verify_chain

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
os.makedirs(DATA, exist_ok=True)

DEPTHS = [1, 2, 3, 4, 6]

# ---------------------------------------------------------------------------
# Transport payload budgets (bytes): usable application payload, not raw PHY
# frame size. Sources as cited in the paper (Section 6, X3).
# ---------------------------------------------------------------------------
TRANSPORT_BUDGETS = {
    # LoRaWAN 1.0.3 Regional Parameters rev. A, EU863-870, application payload N
    # with FOpts empty. DR0-DR2 (SF12-SF10): 51 B. DR4-DR7: 222 B in the
    # repeater-compatible table (Table 8), 242 B if the device never operates
    # behind a repeater (Table 9). US902-928 uplink DR3/DR4 allow 242 B as well.
    "lorawan_dr0": 51,
    "lorawan_dr5_repeater": 222,
    "lorawan_dr5": 242,
    # BLE: one ATT Handle Value Notification or Write Command carries
    # ATT_MTU - 3 bytes. Default ATT_MTU 23 -> 20 B. With ATT_MTU >= 247
    # negotiated and LE Data Length Extension at 251 B, 244 B travel in one
    # link-layer PDU (251 - 4 B L2CAP - 3 B ATT).
    "ble_att_default": 20,
    "ble_dle": 244,
    # IEEE 802.15.4: 127 B is the whole PHY payload (MAC header, FCS and any
    # 6LoWPAN header come out of it), so this is an upper bound.
    "ieee802154_frame": 127,
    # CoAP: RFC 7252 sec. 4.6 -- payload up to 1024 B in a message that fits
    # one IPv6 packet (1280 B MTU) without Block-wise transfer (RFC 7959).
    # Over 6LoWPAN, the adaptation layer still fragments such a datagram.
    "coap_no_blockwise": 1024,
    "mqtt": 1048576,            # MQTT 5.0: effectively unconstrained; 1 MiB broker default
}


def measure_sizes() -> list[dict]:
    rows = []
    for depth in DEPTHS:
        chain, anchor, action = _demo_chain(depth)
        # sanity: chain must verify before we report its size
        verify_chain(chain, anchor, action)
        j = encode_json(chain)
        c = encode_cbor(chain)
        rows.append({"depth": depth, "encoding": "json", "size_bytes": len(j)})
        rows.append({"depth": depth, "encoding": "cbor", "size_bytes": len(c)})
    return rows


def write_sizes(rows: list[dict]) -> None:
    path = os.path.join(DATA, "x4_sizes.csv")
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["depth", "encoding", "size_bytes"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}")


def write_fit_matrix(rows: list[dict]) -> None:
    path = os.path.join(DATA, "x4_fit_matrix.csv")
    transports = list(TRANSPORT_BUDGETS.keys())
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["depth", "encoding", "size_bytes"] + transports)
        for r in rows:
            fits = [
                "1" if r["size_bytes"] <= TRANSPORT_BUDGETS[t] else "0"
                for t in transports
            ]
            w.writerow([r["depth"], r["encoding"], r["size_bytes"]] + fits)
    print(f"wrote {path}")


def print_matrix(rows: list[dict]) -> None:
    transports = list(TRANSPORT_BUDGETS.keys())
    print("\nFits matrix (Y=fits within budget, .=too large):")
    header = f"{'depth':>5} {'enc':>4} {'size':>6} | " + " ".join(f"{t[:10]:>10}" for t in transports)
    print(header)
    print(f"{'budgets':>18} | " + " ".join(f"{TRANSPORT_BUDGETS[t]:>10}" for t in transports))
    for r in rows:
        marks = " ".join(
            f"{('Y' if r['size_bytes'] <= TRANSPORT_BUDGETS[t] else '.'):>10}"
            for t in transports
        )
        print(f"{r['depth']:>5} {r['encoding']:>4} {r['size_bytes']:>6} | {marks}")


if __name__ == "__main__":
    rows = measure_sizes()
    write_sizes(rows)
    write_fit_matrix(rows)
    print_matrix(rows)
    # headline ratio
    jd = {r["depth"]: r["size_bytes"] for r in rows if r["encoding"] == "json"}
    cd = {r["depth"]: r["size_bytes"] for r in rows if r["encoding"] == "cbor"}
    ratios = [cd[d] / jd[d] for d in DEPTHS]
    print(f"\nCBOR/JSON size ratio: min={min(ratios):.3f} max={max(ratios):.3f} "
          f"mean={sum(ratios)/len(ratios):.3f}")
