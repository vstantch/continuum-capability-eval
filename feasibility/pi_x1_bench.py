#!/usr/bin/env python3
"""pi_x1_bench.py -- X1 fog-tier capability-chain verification benchmark.
====================================================================
Re-measures, on the target hardware class (Raspberry Pi 4, fog tier),
the full-chain capability-token verification latency of contgrant.py:
signature checks + attenuation checks + action check, over seeded
delegation chains at depths {1,2,3,4,6}.

Protocol, per depth d:
  * build a deterministic (seeded) demo chain via contgrant._demo_chain(d)
  * WARMUP unmeasured verifications (warms caches / branch predictors;
    CPython has no JIT so this only stabilises the microarchitecture)
  * N measured verifications, each timed with time.perf_counter_ns()
  * report p50 / p90 / p99 / mean / min in microseconds

A CORRECTNESS GATE (the full test_vectors.py suite) runs BEFORE any
timing. If ANY vector fails to accept/reject as expected, the benchmark
refuses to run (fail-closed): a verifier that is not provably correct
must not be timed.

Environment capture follows the group's Pi 4 benchmark protocol: device
model, is_raspberry_pi detection, CPU governor, temperature before AND
after the run, OS, Python, hostname, timestamp. The script WARNS LOUDLY
and marks the JSON if the host is NOT a Raspberry Pi, so a sandbox smoke
test can never be mistaken for a real Pi result.

Usage (on the Pi, from this directory):
    python3 pi_x1_bench.py --platform rented --label mythicbeasts
    python3 pi_x1_bench.py --platform lab    --label lab-pi4-01
    python3 pi_x1_bench.py --platform other  --label sandbox-smoke --quick

Output: x1_results_<platform>_<label>_<YYYYMMDD_HHMMSS>.json (this dir),
containing the environment block, per-depth stats, the correctness-gate
summary, the seeds, and N.

Dependencies: Python stdlib + `cryptography` + `cbor2` only (the two
latter are pulled in transitively by contgrant.py). No numpy / matplotlib
-- keeps the Pi dependency footprint minimal; percentiles are computed in
pure Python (linear interpolation, matching numpy's default method).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# Ensure the local contgrant.py / test_vectors.py are importable regardless
# of the caller's working directory.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from contgrant import _demo_chain, verify_chain  # noqa: E402

DEPTHS = [1, 2, 3, 4, 6]
N_DEFAULT = 10_000
WARMUP_DEFAULT = 1_000
N_QUICK = 500
WARMUP_QUICK = 50
# Seed offset handed to contgrant._demo_chain for each depth. Keys are then
# derived deterministically inside contgrant, so a run is fully reproducible.
SEED_OFFSET = 0


# -- environment capture (mirrors pi4_bench.py) --------------------------------
def _read(path: str) -> str | None:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read().strip("\x00\n ")
    except OSError:
        return None


def detect_pi() -> tuple[str | None, bool, str]:
    """Return (model_string, is_raspberry_pi, source).

    Primary source is the device-tree model; falls back to /proc/cpuinfo
    (Model / Hardware lines) so detection still works on kernels without a
    device-tree node.
    """
    model = _read("/proc/device-tree/model")
    source = "device-tree"
    if not model:
        cpuinfo = _read("/proc/cpuinfo") or ""
        for line in cpuinfo.splitlines():
            key = line.split(":", 1)[0].strip()
            if key == "Model" and ":" in line:
                model = line.split(":", 1)[1].strip()
                source = "cpuinfo"
                break
    is_pi = bool(model and "Raspberry Pi" in model)
    if not is_pi:
        # last-resort scan of cpuinfo (Hardware/Model lines).
        cpuinfo = _read("/proc/cpuinfo") or ""
        if "Raspberry Pi" in cpuinfo:
            is_pi = True
            if not model:
                source = "cpuinfo"
    return model, is_pi, source


def cpu_temp_c() -> float | None:
    """CPU temperature in Celsius.

    Prefers `vcgencmd measure_temp` (the Pi's firmware reading); falls back
    to the generic thermal-zone sysfs file used by pi4_bench.py.
    """
    try:
        out = subprocess.run(
            ["vcgencmd", "measure_temp"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            m = re.search(r"temp=([\d.]+)", out.stdout)
            if m:
                return float(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    raw = _read("/sys/class/thermal/thermal_zone0/temp")
    return int(raw) / 1000.0 if raw and raw.isdigit() else None


def environment() -> dict:
    model, is_pi, source = detect_pi()
    governor = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    freq_khz = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
    return {
        "device_model": model or "unknown",
        "is_raspberry_pi": is_pi,
        "pi_detect_source": source,
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "hostname": socket.gethostname() or platform.node(),
        "cpu_governor": governor,
        "cpu_freq_mhz": int(freq_khz) / 1000.0 if freq_khz and freq_khz.isdigit() else None,
        "temp_before_c": cpu_temp_c(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# -- statistics (pure Python, no numpy) ---------------------------------------
def _percentile(sorted_vals: list[float], q: float) -> float:
    """q-th percentile (q in [0,100]) via linear interpolation between the
    two nearest ranks -- matches numpy.percentile's default ('linear')."""
    n = len(sorted_vals)
    if n == 1:
        return sorted_vals[0]
    rank = (q / 100.0) * (n - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_vals[int(rank)]
    frac = rank - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def _summarise_us(samples_us: list[float]) -> dict:
    s = sorted(samples_us)
    return {
        "n": len(s),
        "p50_us": round(_percentile(s, 50), 3),
        "p90_us": round(_percentile(s, 90), 3),
        "p99_us": round(_percentile(s, 99), 3),
        "mean_us": round(sum(s) / len(s), 3),
        "min_us": round(s[0], 3),
    }


# -- correctness gate (full test_vectors.py suite) ----------------------------
def run_correctness_gate() -> tuple[int, int, list[tuple[str, str]]]:
    """Run every test_ function in test_vectors.py. Returns
    (passed, total, failures)."""
    import test_vectors as tv

    tests = [
        (k, v) for k, v in sorted(vars(tv).items())
        if k.startswith("test_") and callable(v)
    ]
    passed = 0
    failures: list[tuple[str, str]] = []
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as exc:  # noqa: BLE001 -- any failure fails the gate
            failures.append((name, repr(exc)))
    return passed, len(tests), failures


# -- benchmark ----------------------------------------------------------------
def bench_depth(depth: int, n: int, warmup: int) -> dict:
    chain, anchor, action = _demo_chain(depth, seed_offset=SEED_OFFSET)
    # per-depth correctness gate before timing (belt-and-suspenders on top of
    # the full test_vectors suite run earlier).
    verify_chain(chain, anchor, action)
    for _ in range(warmup):
        verify_chain(chain, anchor, action)
    samples_us = [0.0] * n
    for i in range(n):
        t0 = time.perf_counter_ns()
        verify_chain(chain, anchor, action)
        samples_us[i] = (time.perf_counter_ns() - t0) / 1000.0
    stats = _summarise_us(samples_us)
    stats["depth"] = depth
    stats["seed_offset"] = SEED_OFFSET
    return stats


def sustained_depth(depth: int, seconds: float) -> dict:
    """Run full-chain verifications in a tight loop for exactly `seconds` of
    wall time (measured with perf_counter), so an external inline USB power
    meter -- which averages over time -- has a stable, sustained load to read.

    Returns sustained_ops, sustained_wall_s (the *measured* elapsed wall time,
    which will be >= `seconds`), and sustained_ops_per_s.
    """
    chain, anchor, action = _demo_chain(depth, seed_offset=SEED_OFFSET)
    # correctness gate before the sustained loop, same as bench_depth.
    verify_chain(chain, anchor, action)
    ops = 0
    t0 = time.perf_counter()
    deadline = t0 + seconds
    while time.perf_counter() < deadline:
        verify_chain(chain, anchor, action)
        ops += 1
    wall = time.perf_counter() - t0
    return {
        "depth": depth,
        "seed_offset": SEED_OFFSET,
        "sustained_ops": ops,
        "sustained_wall_s": round(wall, 6),
        "sustained_ops_per_s": round(ops / wall, 3) if wall > 0 else None,
        "requested_s": seconds,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="X1 fog-tier verify-latency benchmark")
    ap.add_argument("--platform", required=True, choices=["rented", "lab", "other"],
                    help="host provenance, recorded in the result JSON")
    ap.add_argument("--label", default="", help="free-text label, e.g. "
                    "'mythicbeasts' or 'lab-pi4-01' (goes in the filename)")
    ap.add_argument("--quick", action="store_true",
                    help=f"reduced run for smoke tests (N={N_QUICK}, "
                    f"warmup={WARMUP_QUICK}); NOT for reportable numbers")
    ap.add_argument("--sustained", type=float, default=None, metavar="SECONDS",
                    help="board-level energy mode: after the normal per-depth "
                    "latency stats, run an additional sustained phase per depth "
                    "that loops full-chain verifications for exactly SECONDS of "
                    "wall time. Prints stderr START/END banners (so the operator "
                    "can align an inline USB power-meter reading) and pauses 10 s "
                    "between depths for an idle re-read. Records sustained_ops / "
                    "sustained_wall_s / sustained_ops_per_s per depth.")
    ap.add_argument("--idle-baseline", type=float, default=None, metavar="SECONDS",
                    help="before any benching, sleep SECONDS (with START/END "
                    "banners) so the operator can read idle power from the meter; "
                    "recorded as idle_baseline_s in the JSON energy block.")
    ap.add_argument("--power-idle-w", type=float, default=None, metavar="WATTS",
                    help="manual inline-USB-meter idle reading (watts), stored "
                    "verbatim under energy.operator_reported_power. If both "
                    "--power-idle-w and --power-load-w are given AND sustained "
                    "data exists, per-depth board-level energy_per_op_uj is "
                    "computed from them.")
    ap.add_argument("--power-load-w", type=float, default=None, metavar="WATTS",
                    help="manual inline-USB-meter under-load reading (watts), "
                    "stored verbatim; see --power-idle-w.")
    args = ap.parse_args()

    n = N_QUICK if args.quick else N_DEFAULT
    warmup = WARMUP_QUICK if args.quick else WARMUP_DEFAULT

    # --- correctness gate FIRST; refuse to bench if anything fails -----------
    print("running correctness gate (test_vectors.py) ...", file=sys.stderr)
    passed, total, failures = run_correctness_gate()
    print(f"correctness gate: {passed}/{total} vectors passed", file=sys.stderr)
    if failures:
        for name, err in failures:
            print(f"  FAIL {name}: {err}", file=sys.stderr)
        sys.exit("REFUSING TO BENCH: correctness gate failed (fail-closed). "
                 "A verifier that is not provably correct must not be timed.")

    env = environment()

    # --- loud non-Pi warning -------------------------------------------------
    sandbox = not env["is_raspberry_pi"]
    if sandbox:
        print("=" * 72, file=sys.stderr)
        print("WARNING: host is '%s' -- NOT a Raspberry Pi." % env["device_model"],
              file=sys.stderr)
        print("These numbers are a SANDBOX SMOKE TEST ONLY and must NEVER be "
              "reported as Pi results.", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
    if env["cpu_governor"] not in (None, "performance"):
        print(f"NOTE: cpu governor is '{env['cpu_governor']}'. For stable numbers: "
              "sudo cpufreq-set -g performance (or accept it and report it).",
              file=sys.stderr)
    if args.quick:
        print(f"NOTE: --quick set (N={n}, warmup={warmup}); reduced run, not "
              "reportable.", file=sys.stderr)

    print(f"host: {env['device_model']} | python {env['python']} | "
          f"governor {env['cpu_governor']} | temp {env['temp_before_c']} C | "
          f"N={n} warmup={warmup}", file=sys.stderr)

    # --- idle baseline (operator reads idle power from the meter) ------------
    idle_baseline_s = None
    if args.idle_baseline is not None:
        print("=" * 72, file=sys.stderr)
        print(f"IDLE BASELINE START ({args.idle_baseline} seconds)", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        t0 = time.perf_counter()
        time.sleep(args.idle_baseline)
        idle_baseline_s = round(time.perf_counter() - t0, 6)
        print("IDLE BASELINE END", file=sys.stderr)

    # --- timing --------------------------------------------------------------
    per_depth = {}
    seeds = {}
    for d in DEPTHS:
        r = bench_depth(d, n, warmup)
        per_depth[str(d)] = r
        seeds[str(d)] = SEED_OFFSET
        print(f"depth={d}: p50={r['p50_us']:.2f}us p90={r['p90_us']:.2f}us "
              f"p99={r['p99_us']:.2f}us mean={r['mean_us']:.2f}us min={r['min_us']:.2f}us"
              + ("  (SANDBOX)" if sandbox else ""), file=sys.stderr)

    # --- sustained phase (board-level energy mode) ---------------------------
    sustained_by_depth = {}
    if args.sustained is not None:
        for idx, d in enumerate(DEPTHS):
            print("=" * 72, file=sys.stderr)
            print(f"SUSTAINED depth={d} START ({args.sustained} seconds)",
                  file=sys.stderr)
            print("=" * 72, file=sys.stderr)
            sr = sustained_depth(d, args.sustained)
            sustained_by_depth[str(d)] = sr
            print(f"SUSTAINED depth={d} END "
                  f"(ops={sr['sustained_ops']} wall={sr['sustained_wall_s']}s "
                  f"{sr['sustained_ops_per_s']} ops/s)"
                  + ("  (SANDBOX)" if sandbox else ""), file=sys.stderr)
            if idx != len(DEPTHS) - 1:
                print("IDLE GAP (10 seconds) -- re-read idle power now",
                      file=sys.stderr)
                time.sleep(10.0)

    # --- energy block --------------------------------------------------------
    # verbatim manual meter readings (may be None).
    operator_reported_power = {
        "idle_w": args.power_idle_w,
        "load_w": args.power_load_w,
        "note": "manual inline USB power-meter readings entered by the operator; "
                "NOT measured by this script.",
    }
    have_power = args.power_idle_w is not None and args.power_load_w is not None
    energy_per_op = {}
    if have_power and sustained_by_depth:
        delta_w = args.power_load_w - args.power_idle_w
        for k, sr in sustained_by_depth.items():
            ops = sr["sustained_ops"]
            wall = sr["sustained_wall_s"]
            energy_per_op[k] = {
                "energy_per_op_uj": (
                    round(delta_w * wall / ops * 1e6, 3) if ops > 0 else None
                ),
                "board_level": True,
                "note": "(load_w - idle_w) * sustained_wall_s / sustained_ops, "
                        "in microjoules; derived from manual meter readings.",
            }
    energy = {
        "board_level_mode": args.sustained is not None,
        "idle_baseline_s": idle_baseline_s,
        "sustained_seconds_requested": args.sustained,
        "sustained_by_depth": sustained_by_depth,
        "operator_reported_power": operator_reported_power,
        "energy_per_op_by_depth": energy_per_op,
    }

    env["temp_after_c"] = cpu_temp_c()

    out = {
        "benchmark": "pi_x1_bench",
        "tier": "X1-fog",
        "platform": args.platform,
        "label": args.label,
        "sandbox_indicative": sandbox,
        "warning": (
            "SANDBOX SMOKE TEST -- host is not a Raspberry Pi; do not report."
            if sandbox else None
        ),
        "quick": args.quick,
        "N": n,
        "warmup": warmup,
        "depths": DEPTHS,
        "seeds": seeds,
        "correctness_gate": {
            "suite": "test_vectors.py",
            "vectors_passed": passed,
            "vectors_total": total,
            "all_passed": True,
        },
        "environment": env,
        "results_by_depth": per_depth,
        "energy": energy,
    }

    label_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", args.label).strip("-") or "nolabel"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"x1_results_{args.platform}_{label_slug}_{ts}.json"
    fpath = os.path.join(HERE, fname)
    with open(fpath, "w") as f:
        f.write(json.dumps(out, indent=2))
    print(f"\nwrote {fpath}", file=sys.stderr)

    if env["temp_after_c"] and env["temp_after_c"] > 80:
        print("WARNING: temp_after > 80 C -- possible thermal throttling; rerun "
              "after cooldown and compare.", file=sys.stderr)


if __name__ == "__main__":
    main()
