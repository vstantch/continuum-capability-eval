"""check_x1_provenance.py -- tie the X1 CSVs to the raw board JSONs.

Every reportable row in data/bench_verify.csv (sandbox_indicative=false) and
every row in data/bench_energy.csv must equal the corresponding field in the
unedited result JSON produced on the board by pi_x1_bench.py. Exits non-zero
on the first mismatch.

idle_w and load_w in bench_energy.csv are the operator's inline-meter
readings; the script does not measure them, so they have no JSON source.
"""

from __future__ import annotations

import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
RESULTS = os.path.join(HERE, "results", "x1")

# (platform, label) -> result file backing the latency rows
LATENCY_SOURCES = {
    ("rented", "mythicbeasts"): "x1_results_rented_mythicbeasts_20260720_051348.json",
    ("lab", "lab-pi4-01"): "x1_results_lab_lab-pi4-01_20260727_132329.json",
    ("lab", "lab-pi3-01"): "x1_results_lab_lab-pi3-01_20260727_135056.json",
}
# (platform, label) -> result file backing the sustained-throughput rows
ENERGY_SOURCES = {
    ("lab", "lab-pi4-01"): "x1_results_lab_lab-pi4-01_20260727_144309.json",
}
LATENCY_FIELDS = ["n", "p50_us", "p99_us", "mean_us", "min_us"]


def load(name: str) -> dict:
    with open(os.path.join(RESULTS, name)) as f:
        d = json.load(f)
    env = d["environment"]
    gate = d["correctness_gate"]
    if d["sandbox_indicative"] or not env["is_raspberry_pi"]:
        sys.exit(f"{name}: not a real-board result")
    if gate["vectors_passed"] != gate["vectors_total"] or not gate["all_passed"]:
        sys.exit(f"{name}: correctness gate did not pass")
    return d


def read_csv(name: str) -> list[dict]:
    with open(os.path.join(DATA, name)) as f:
        return list(csv.DictReader(f))


def main() -> None:
    checked = 0
    for r in read_csv("bench_verify.csv"):
        if r["sandbox_indicative"].lower() != "false":
            continue
        key = (r["platform"], r["label"])
        if key not in LATENCY_SOURCES:
            sys.exit(f"bench_verify.csv: no result file for {key}")
        res = load(LATENCY_SOURCES[key])["results_by_depth"][r["depth"]]
        for fld in LATENCY_FIELDS:
            if float(r[fld]) != float(res[fld]):
                sys.exit(f"bench_verify.csv {key} depth {r['depth']} {fld}: "
                         f"csv {r[fld]} != json {res[fld]}")
        checked += 1
    for r in read_csv("bench_energy.csv"):
        key = (r["platform"], r["label"])
        if key not in ENERGY_SOURCES:
            sys.exit(f"bench_energy.csv: no result file for {key}")
        sus = load(ENERGY_SOURCES[key])["energy"]["sustained_by_depth"][r["depth"]]
        if float(r["sustained_ops_per_s"]) != float(sus["sustained_ops_per_s"]):
            sys.exit(f"bench_energy.csv {key} depth {r['depth']}: "
                     f"csv {r['sustained_ops_per_s']} != json {sus['sustained_ops_per_s']}")
        checked += 1
    print(f"X1 provenance: {checked} CSV rows match their board JSONs")


if __name__ == "__main__":
    main()
