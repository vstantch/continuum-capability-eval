# feasibility/

Reference implementation, experiment scripts, data and generated tables. The
top-level `README.md` maps each script to the paper's experiments and gives the
reproduction steps; this file records the model details the scripts assume.

## Seeds and determinism

- `x2_sim.py`: `BASE_SEED = 20260718`, `N_TRIALS = 10_000`. Each grid point
  derives its own seed, so results do not depend on iteration order.
- `contgrant._demo_chain`: keys derived from a fixed byte seed, no OS
  randomness, so demo chains and their sizes are reproducible.
- `pi_x1_bench.py`: no RNG in the timed path; N = 10,000 per depth after
  1,000 warmup verifications; depths 1, 2, 3, 4, 6.

## X2 grid

- Offline duration `D`: 1 min to 48 h, 20 log-spaced points.
- Expiry horizon `H`: 15 min, 1 h, 8 h, 24 h, 168 h.
- Revocation epoch `E`: 1 min, 15 min, 1 h, 8 h.

## Model

- Caveats are conjunctive, negation-free and attenuation-only: `topic_prefix`
  (child extends the parent prefix), `rate_limit_per_min` (child <= parent),
  `geofence` (child circle inside parent circle, great-circle test),
  `valid_from`/`valid_until` (child window inside parent window).
- The verifier fails closed: an unknown caveat field, a malformed value,
  broken key succession, a bad signature, a widening caveat, or an action
  outside the effective caveat set is a rejection.
- Availability = min(time-to-expiry, D) / D, with time-to-expiry ~ U(0, H)
  at the start of the outage. Staleness (spec) = max(0, min(t_exp, D) - r)
  for a revocation at r ~ U(0, D). The epoch-aware column adds a wait
  ~ U(0, E) after reconnect; the spec column does not depend on E.
- Transport budgets in `x4_sizes.TRANSPORT_BUDGETS` are usable application
  payloads, not raw frame sizes; the sources are listed next to each value.
