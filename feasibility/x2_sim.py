"""x2_sim.py -- availability / staleness simulation (seeded, deterministic).

Question: for a capability-based scheme where a device holds a short-lived,
locally-verifiable capability, how does disconnection duration D, capability
expiry horizon H, and revocation epoch length E trade off availability vs.
revocation staleness -- compared to a remote-PDP baseline that CANNOT authorize
anything while the device is disconnected?

Model
-----
* At the moment the device goes offline (t=0) it holds a legitimately-issued,
  still-valid capability whose remaining time-to-expiry is t_exp ~ U(0, H)
  (the device may go offline at any point in the capability's lifetime).
* The device is offline for duration D. While offline it can still EXERCISE the
  capability locally until it expires. Epoch staleness does NOT block honest use.

Metrics (per grid point, over N=10_000 seeded trials)
* availability = fraction of the offline window [0,D] during which the held,
  unexpired capability is exercisable = min(t_exp, D) / D.  It fails once
  expiry passes.  Reported: mean and min over trials.
* staleness exposure = worst-case time a capability revoked at a uniformly
  random moment r ~ U(0,D) during the offline window remains honored
  = min(time-to-expiry, remainder-of-offline-window)
  = max(0, min(t_exp, D) - r).            [primary metric, per spec -- no E]
  Reported: mean and max over trials.
  Additionally we report an epoch-aware variant that credits the revocation
  epoch E: after reconnect the device only refreshes revocation state at the
  next epoch boundary, so honored time may extend by up to a uniform wait in
  [0,E]:  staleness_epoch = max(0, min(t_exp, D + w) - r), w ~ U(0,E).
  (staleness_epoch is a labelled extension; staleness_spec is the spec metric.)

Baseline: remote-PDP availability during full disconnection = 0 (cannot reach
the decision point), independent of D,H,E.

Determinism: a fixed BASE_SEED plus a per-grid-point offset seeds a dedicated
numpy Generator, so results are reproducible and independent of grid order.

Outputs:
  data/x2_availability.csv
  data/x2_staleness.csv
"""

from __future__ import annotations

import csv
import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
os.makedirs(DATA, exist_ok=True)

# ---------------------------------------------------------------------------
# Seeds (RECORD THESE).
# ---------------------------------------------------------------------------
BASE_SEED = 20260718  # fixed; change only to regenerate
N_TRIALS = 10_000

MIN = 60
HOUR = 3600

# Offline duration grid: 1 min .. 48 h, log-spaced (20 points).
D_GRID = np.unique(
    np.round(np.logspace(np.log10(1 * MIN), np.log10(48 * HOUR), 20)).astype(int)
).tolist()

# Capability expiry horizon grid.
H_GRID = [15 * MIN, 1 * HOUR, 8 * HOUR, 24 * HOUR, 168 * HOUR]

# Revocation epoch length grid.
E_GRID = [1 * MIN, 15 * MIN, 1 * HOUR, 8 * HOUR]


def _rng(*idx: int) -> np.random.Generator:
    # Distinct, order-independent stream per grid point.
    off = 0
    for k, v in enumerate(idx):
        off = off * 1_000_003 + (v + 1)
    return np.random.default_rng(BASE_SEED + (off % 2_000_000_000))


def simulate_availability() -> list[dict]:
    rows = []
    for di, D in enumerate(D_GRID):
        for hi, H in enumerate(H_GRID):
            g = _rng(1, di, hi)
            t_exp = g.uniform(0.0, H, N_TRIALS)
            avail = np.minimum(t_exp, D) / D
            rows.append(
                {
                    "D_seconds": D,
                    "H_seconds": H,
                    "n_trials": N_TRIALS,
                    "mean_availability": round(float(avail.mean()), 6),
                    "min_availability": round(float(avail.min()), 6),
                    "remote_pdp_availability": 0.0,
                }
            )
    return rows


def simulate_staleness() -> list[dict]:
    rows = []
    for di, D in enumerate(D_GRID):
        for hi, H in enumerate(H_GRID):
            for ei, E in enumerate(E_GRID):
                g = _rng(2, di, hi, ei)
                t_exp = g.uniform(0.0, H, N_TRIALS)
                r = g.uniform(0.0, D, N_TRIALS)
                w = g.uniform(0.0, E, N_TRIALS)
                # primary (spec): honored until min(expiry, reconnect)
                honored_until = np.minimum(t_exp, D)
                stale_spec = np.maximum(0.0, honored_until - r)
                # epoch-aware extension: reconnect + wait to next epoch boundary
                honored_until_e = np.minimum(t_exp, D + w)
                stale_epoch = np.maximum(0.0, honored_until_e - r)
                rows.append(
                    {
                        "D_seconds": D,
                        "H_seconds": H,
                        "E_seconds": E,
                        "n_trials": N_TRIALS,
                        "mean_staleness_spec_s": round(float(stale_spec.mean()), 4),
                        "max_staleness_spec_s": round(float(stale_spec.max()), 4),
                        "mean_staleness_epoch_s": round(float(stale_epoch.mean()), 4),
                        "max_staleness_epoch_s": round(float(stale_epoch.max()), 4),
                    }
                )
    return rows


def write_csv(path: str, rows: list[dict], fields: list[str]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}  ({len(rows)} rows)")


if __name__ == "__main__":
    print(f"BASE_SEED={BASE_SEED}  N_TRIALS={N_TRIALS}")
    print(f"D_GRID ({len(D_GRID)} pts): {D_GRID}")
    print(f"H_GRID: {H_GRID}")
    print(f"E_GRID: {E_GRID}")

    a = simulate_availability()
    write_csv(
        os.path.join(DATA, "x2_availability.csv"),
        a,
        ["D_seconds", "H_seconds", "n_trials", "mean_availability",
         "min_availability", "remote_pdp_availability"],
    )
    s = simulate_staleness()
    write_csv(
        os.path.join(DATA, "x2_staleness.csv"),
        s,
        ["D_seconds", "H_seconds", "E_seconds", "n_trials",
         "mean_staleness_spec_s", "max_staleness_spec_s",
         "mean_staleness_epoch_s", "max_staleness_epoch_s"],
    )

    # A couple of representative readouts.
    print("\nRepresentative availability (capability scheme vs remote-PDP=0):")
    for r in a:
        if r["D_seconds"] in (D_GRID[0], D_GRID[len(D_GRID)//2], D_GRID[-1]) and \
           r["H_seconds"] in (1 * HOUR, 24 * HOUR):
            print(f"  D={r['D_seconds']:6d}s H={r['H_seconds']:6d}s "
                  f"avail={r['mean_availability']:.3f}  (remote-PDP=0)")
