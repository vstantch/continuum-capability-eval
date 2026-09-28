# continuum-capability-eval

Reproducibility artifact for the manuscript *Authorization That Survives Disconnection: Capability-Based Security and Portable Evidence for the Cloud-Fog-Edge Continuum* (V. Stantchev), prepared for the MDPI *Future Internet* special issue "Trustworthy AI and Secure Cloud-Fog-Edge Continuum for the Internet of Things".

Every number in the paper's evaluation comes from this repository: a reference implementation of cloud-rooted, attenuation-only capability chains, the correctness vectors that gate it, the scripts that produce each result CSV, the raw result files from the benchmark boards, and the script that turns the CSVs into the paper's LaTeX tables.

## What is here

| Paper | Question | Script | Data | Table |
|---|---|---|---|---|
| X1 | Chain verification latency on fog- and gateway-class boards | `pi_x1_bench.py` (runs on the board) | `results/x1/*.json` → `data/bench_verify.csv` | `generated/bench_table.tex` |
| X1 | Board-level energy, lab Pi 4 | `pi_x1_bench.py --idle-baseline 60 --sustained 60` | `results/x1/…144309.json` → `data/bench_energy.csv` | `generated/bench_energy_table.tex` |
| X2 | Availability and revocation staleness under disconnection | `x2_sim.py` | `data/x2_availability.csv`, `data/x2_staleness.csv` | `generated/x2_table.tex` |
| X3 | Credential size against transport payload budgets | `x4_sizes.py` | `data/x4_sizes.csv`, `data/x4_fit_matrix.csv` | `generated/x4_table.tex` |

All paths are under `feasibility/`. The paper numbers the size experiment X3; the scripts and files keep the working name `x4_*`.

`contgrant.py` is the reference implementation: Ed25519 per-hop signatures, child-key succession, four caveats (topic prefix, rate, geofence, validity window) that may only narrow, a fail-closed verifier, and JSON and CBOR encodings. `test_vectors.py` holds the 19 golden and adversarial vectors. `mkresults.py` writes the tables. `check_x1_provenance.py` confirms that every X1 row in the CSVs equals the corresponding field in the board's result file.

## Reproduce

Python 3.11, dependencies pinned by hash:

```bash
python3.11 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
cd feasibility
../.venv/bin/python test_vectors.py          # 19/19 must pass
../.venv/bin/python x4_sizes.py              # X3 sizes and transport fit
../.venv/bin/python x2_sim.py                # X2, seeded (base seed 20260718, 10,000 trials per point)
../.venv/bin/python check_x1_provenance.py   # X1 CSVs against board JSONs
../.venv/bin/python mkresults.py             # regenerate generated/*.tex
git diff --exit-code                         # nothing may change
```

The X2 and X3 outputs are deterministic and regenerate byte-identical; CI checks this on every push.

X1 has to be measured on the board itself. Copy `feasibility/` to a Raspberry Pi, install the same requirements in a venv, set the `performance` governor, and run

```bash
python3 pi_x1_bench.py --platform lab --label <board-label>
```

The script runs the full vector suite first and refuses to time a verifier that fails any vector. It records device model, governor, clock, kernel, Python version and temperature before and after, and stamps any non-Pi host as `sandbox_indicative`, so a laptop run cannot pass for a board result. Move the JSON into `results/x1/`, add its rows to the CSV, and extend the source map in `check_x1_provenance.py`.

## Hardware runs

| Label | Board | Clock | Governor | Date | Result file |
|---|---|---|---|---|---|
| `mythicbeasts` (rented) | Raspberry Pi 4 Model B Rev 1.4 | 1.5 GHz | performance | 2026-07-20 | `x1_results_rented_mythicbeasts_20260720_051348.json` |
| `lab-pi4-01` | Raspberry Pi 4 Model B Rev 1.5 | 1.8 GHz | performance | 2026-07-27 | `x1_results_lab_lab-pi4-01_20260727_132329.json` |
| `lab-pi3-01` | Raspberry Pi 3 Model B Rev 1.2 | 1.2 GHz | performance | 2026-07-27 | `x1_results_lab_lab-pi3-01_20260727_135056.json` |
| `lab-pi4-01` energy | Raspberry Pi 4 Model B Rev 1.5 | 1.8 GHz | ondemand | 2026-07-27 | `x1_results_lab_lab-pi4-01_20260727_144309.json` |

Every run passed the 19-vector gate and used N = 10,000 timed verifications per depth after 1,000 warmup runs. Platforms are reported side by side and never merged or averaged: the two Pi 4s are the same model on different hosting, and a gap between them is a finding. The energy run used `ondemand` because inserting the meter power-cycles the board; its clock held 1.8 GHz and its p50 latencies match the `performance` run within 0.5%.

The idle and load wattages in `bench_energy.csv` (1.84 W, 3.02 W) are the operator's readings from an inline USB-C meter. The script does not measure them, so they have no source in the JSON. Sustained throughput does, and the provenance check covers it.

The hardware benchmarks were run by Kunal Gawande (SRH University Heidelberg). Result files are published as the boards wrote them.

`bench_verify.csv` also keeps five rows marked `sandbox_indicative=true` from an early development-host run. `mkresults.py` never renders them and the paper does not cite them.

## Not in this release

The paper specifies two components it does not measure: the `no_std` Rust verifier for microcontroller-class devices and the OP-TEE trusted application that attests the fog verifier. Neither is in this repository. When they exist, they get certified against the same vector suite.

This is research code. It demonstrates and measures a design; it is not a hardened authorization library and should not guard a production system.

## License

Code: MIT (`LICENSE`). Data and generated tables (`feasibility/data/`, `feasibility/results/`, `feasibility/generated/`): CC BY 4.0 (`LICENSE-DATA`).

## Citation

See `CITATION.cff`. The paper's Data Availability Statement cites the tag of the commit that produced its tables.

## Contact

Vladimir Stantchev, SRH University Heidelberg, stantchev@computer.org. Security reports: see `SECURITY.md`.
