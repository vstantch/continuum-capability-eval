"""mkresults.py -- read CSVs, emit booktabs LaTeX tables to generated/.

Produces:
  generated/x4_table.tex     -- size (JSON vs CBOR) and transport fit by depth
  generated/x2_table.tex     -- availability/staleness at representative points
  generated/bench_table.tex  -- measured verify latency by depth (per platform)
  generated/bench_energy_table.tex -- measured board-level energy (lab Pi 4)

X4 (sizes) are exact serializations and X2 is a seeded simulation study, so
both are final; X1 (bench/energy) carries measured hardware runs.
"""

from __future__ import annotations

import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
GEN = os.path.join(HERE, "generated")
os.makedirs(GEN, exist_ok=True)

MIN = 60
HOUR = 3600
POWER_UNC_W = 0.03  # read uncertainty of each meter reading (idle, load)


def read_csv(name: str) -> list[dict]:
    with open(os.path.join(DATA, name)) as f:
        return list(csv.DictReader(f))


def _fmt_dur(s: int) -> str:
    s = int(s)
    if s % HOUR == 0:
        return f"{s // HOUR}h"
    if s % MIN == 0:
        return f"{s // MIN}min"
    return f"{s}s"


# ---------------------------------------------------------------------------
# x4: size + transport fit
# ---------------------------------------------------------------------------
def make_x4_table() -> str:
    sizes = read_csv("x4_sizes.csv")
    by_depth: dict[int, dict[str, int]] = {}
    for r in sizes:
        by_depth.setdefault(int(r["depth"]), {})[r["encoding"]] = int(r["size_bytes"])
    depths = sorted(by_depth)

    fit = read_csv("x4_fit_matrix.csv")
    transports = [c for c in fit[0].keys() if c not in ("depth", "encoding", "size_bytes")]
    fitmap = {(int(r["depth"]), r["encoding"]): r for r in fit}

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Serialized capability-chain size and transport-payload fit "
                 r"by delegation depth (compact JSON vs.\ CBOR with integer keys). "
                 r"Sizes are exact serializations. Each transport column gives the "
                 r"application-payload budget under the stated configuration: LoRaWAN "
                 r"EU863-870 with FOpts empty, at DR0 and at DR5 with and without "
                 r"repeater compatibility (Regional Parameters 1.0.3, Tables 8--9); "
                 r"BLE as one ATT notification or Write Command at the default "
                 r"ATT\_MTU of 23 and at ATT\_MTU${}\geq{}$247 with LE Data Length "
                 r"Extension at 251\,B; the 127\,B IEEE 802.15.4 PHY payload as an "
                 r"upper bound; CoAP without Block-wise transfer in one IPv6 packet; "
                 r"MQTT at a 1\,MiB broker limit (Section~\ref{sec:eval-x4}).}")
    lines.append(r"\label{tab:x4-sizes}")
    lines.append(r"\begin{tabular}{r rr r " + "c" * len(transports) + r"}")
    lines.append(r"\toprule")
    hdr = (r"Depth & JSON (B) & CBOR (B) & CBOR/JSON & "
           + " & ".join(_tex_transport(t) for t in transports) + r" \\")
    lines.append(hdr)
    lines.append(r"\midrule")
    for d in depths:
        j = by_depth[d]["json"]
        c = by_depth[d]["cbor"]
        ratio = c / j
        # fit marks: Y if BOTH json and cbor fit? show cbor fit (smaller); mark
        # C if only cbor fits, Y if both, . if neither
        marks = []
        for t in transports:
            jf = fitmap[(d, "json")][t] == "1"
            cf = fitmap[(d, "cbor")][t] == "1"
            if jf and cf:
                marks.append(r"\checkmark")
            elif cf:
                marks.append(r"C")
            else:
                marks.append(r"--")
        lines.append(f"{d} & {j} & {c} & {ratio:.3f} & " + " & ".join(marks) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\par\smallskip")
    lines.append(r"\footnotesize Budgets in bytes. \checkmark: both encodings fit; "
                 r"C: only CBOR fits; --: neither fits.")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


TRANSPORT_LABELS = {
    "lorawan_dr0": "LoRa DR0 (51)",
    "lorawan_dr5_repeater": "LoRa DR5 rep. (222)",
    "lorawan_dr5": "LoRa DR5 (242)",
    "ble_att_default": "BLE default (20)",
    "ble_dle": "BLE DLE (244)",
    "ieee802154_frame": "802.15.4 (127)",
    "coap_no_blockwise": "CoAP (1024)",
    "mqtt": "MQTT (1\\,MiB)",
}


def _tex_transport(t: str) -> str:
    return r"\rotatebox{90}{" + TRANSPORT_LABELS.get(t, t.replace("_", r"\_")) + "}"


# ---------------------------------------------------------------------------
# x2: availability + staleness compact summary
# ---------------------------------------------------------------------------
def make_x2_table() -> str:
    avail = read_csv("x2_availability.csv")
    stale = read_csv("x2_staleness.csv")

    # Representative offline durations and horizons.
    Ds = sorted({int(r["D_seconds"]) for r in avail})
    rep_D = [Ds[0], Ds[len(Ds) // 2], Ds[-1]]  # short / mid / long
    rep_H = [1 * HOUR, 8 * HOUR, 24 * HOUR]
    rep_E = 15 * MIN  # representative epoch for staleness column

    avmap = {(int(r["D_seconds"]), int(r["H_seconds"])): r for r in avail}
    stmap = {(int(r["D_seconds"]), int(r["H_seconds"]), int(r["E_seconds"])): r
             for r in stale}

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Availability and revocation exposure at representative grid "
                 r"points (offline duration $D$, expiry horizon $H$). Avail.: fraction of "
                 r"the offline window during which a credential that was valid at "
                 r"disconnection stays exercisable; an online-only PDP has availability "
                 r"$0$ throughout. Live: fraction of trials in which the credential is "
                 r"still honored when it is revoked. Exposure: time a revoked credential "
                 r"stays honored, as a mean over all trials (credentials that expired "
                 r"before revocation count as $0$) and over live trials only; the "
                 r"epoch-aware column adds the wait for the next epoch after reconnect "
                 r"at $E{=}15$\,min. Exposure is in seconds (s), minutes (m), or hours (h). "
                 r"10{,}000 seeded trials per point; Section~\ref{sec:eval-x2} gives the "
                 r"sampling model.}")
    lines.append(r"\label{tab:x2-avail}")
    lines.append(r"\begin{tabular}{ll r r rr r}")
    lines.append(r"\toprule")
    lines.append(r" & & & & \multicolumn{3}{c}{Mean exposure} \\")
    lines.append(r"\cmidrule(lr){5-7}")
    lines.append(r"$D$ & $H$ & Avail. & Live & all & live & live, $E{=}15$m \\")
    lines.append(r"\midrule")
    for D in rep_D:
        for H in rep_H:
            a = avmap[(D, H)]
            s = stmap[(D, H, rep_E)]
            lines.append(
                f"{_fmt_D(D)} & {_fmt_dur(H)} & "
                f"{float(a['mean_availability']):.3f} & "
                f"{float(s['frac_live_at_revocation']):.3f} & "
                f"{_fmt_stale(float(s['mean_staleness_spec_s']))} & "
                f"{_fmt_stale(float(s['mean_staleness_spec_live_s']))} & "
                f"{_fmt_stale(float(s['mean_staleness_epoch_live_s']))} \\\\"
            )
        lines.append(r"\addlinespace")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def _fmt_D(s: int) -> str:
    # The middle grid point (3971 s) is the log-spaced point nearest one hour.
    if s % MIN == 0 or s % HOUR == 0:
        return _fmt_dur(s)
    return f"{s / MIN:.0f}min"


def _fmt_stale(s: float) -> str:
    if s >= HOUR:
        return f"{s/HOUR:.2f}h"
    if s >= MIN:
        return f"{s/MIN:.1f}m"
    return f"{s:.0f}s"


# ---------------------------------------------------------------------------
# bench: verify latency
# ---------------------------------------------------------------------------
def make_bench_table() -> str:
    """X1 table: one column group per REPORTABLE platform (sandbox_indicative=false).

    Sandbox rows stay in the CSV for provenance but are never rendered.
    Platforms are rendered side by side and never merged or averaged; when the
    lab Pi 4 rows land, they appear as an additional column group automatically.
    """
    rows = [r for r in read_csv("bench_verify.csv")
            if r.get("sandbox_indicative", "true").lower() == "false"]
    if not rows:
        raise SystemExit("bench: no reportable (non-sandbox) rows in bench_verify.csv")
    platforms = []
    for r in rows:
        key = (r["platform"], r["label"])
        if key not in platforms:
            platforms.append(key)
    depths = sorted({int(r["depth"]) for r in rows})
    by = {(r["platform"], r["label"], int(r["depth"])): r for r in rows}

    PROVENANCE = {
        ("rented", "mythicbeasts"):
            "hosted bare-metal Raspberry Pi 4 Model B Rev 1.4 (Mythic Beasts; "
            "aarch64, 64-bit OS, Python 3.11.2, \\texttt{performance} governor, "
            "1.5\\,GHz), 10{,}000 verifications per depth after 1{,}000 warmup, "
            "correctness gate 19/19 (v1.0 suite), temperature 37.9$\\rightarrow$40.9\\,$^{\\circ}$C",
        ("lab", "lab-pi4-01"):
            "lab Raspberry Pi 4 Model B Rev 1.5 (aarch64, Bookworm 64-bit, "
            "Python 3.11.2, \\texttt{performance} governor, 1.8\\,GHz), 10{,}000 "
            "verifications per depth after 1{,}000 warmup, correctness gate 19/19 (v1.0 suite), "
            "temperature 50.1$\\rightarrow$55.0\\,$^{\\circ}$C",
        ("lab", "lab-pi3-01"):
            "lab Raspberry Pi 3 Model B Rev 1.2 (Cortex-A53, aarch64, Bookworm "
            "64-bit, Python 3.11.2, \\texttt{performance} governor, 1.2\\,GHz), "
            "10{,}000 verifications per depth after 1{,}000 warmup, correctness "
            "gate 19/19 (v1.0 suite), temperature 47.2$\\rightarrow$56.4\\,$^{\\circ}$C",
    }
    head = {
        ("rented", "mythicbeasts"): "Fog (rented Pi 4)",
        ("lab", "lab-pi4-01"): "Fog (lab Pi 4)",
        ("lab", "lab-pi3-01"): "Gateway (lab Pi 3)",
    }

    prov = "; ".join(PROVENANCE.get(p, f"{p[0]}/{p[1]}") for p in platforms)
    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{\textbf{Measured (this work).} X1 --- full delegation-chain "
                 r"verification latency on the fog reference platform, by chain depth: "
                 + prov + r". Platforms are reported per column group and never merged.}")
    lines.append(r"\label{tab:bench-verify}")
    colspec = "r " + " ".join("rrr" for _ in platforms)
    lines.append(r"\begin{tabular}{" + colspec + "}")
    lines.append(r"\toprule")
    groups = " & ".join(
        r"\multicolumn{3}{c}{" + head.get(p, p[1]) + "}" for p in platforms)
    lines.append(r"Depth & " + groups + r" \\")
    sub = " & ".join(r"p50 ($\mu$s) & p99 ($\mu$s) & mean ($\mu$s)" for _ in platforms)
    lines.append(r" & " + sub + r" \\")
    lines.append(r"\midrule")
    for dpt in depths:
        cells = []
        for p in platforms:
            r = by.get((p[0], p[1], dpt))
            if r is None:
                cells.append("-- & -- & --")
            else:
                cells.append(f"{float(r['p50_us']):.1f} & "
                             f"{float(r['p99_us']):.1f} & {float(r['mean_us']):.1f}")
        lines.append(f"{dpt} & " + " & ".join(cells) + r" \\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# bench energy: board-level energy per verification (lab Pi 4 only)
# ---------------------------------------------------------------------------
def make_energy_table() -> str:
    """X1 energy table: whole-board energy per verification by depth.

    Energy is the DELTA over the idle baseline (load minus idle whole-board
    watts, eyeball-read off an inline USB meter) divided by sustained
    throughput. Reported only for the physically accessible lab Pi 4.
    """
    rows = read_csv("bench_energy.csv")
    if not rows:
        raise SystemExit("energy: no rows in bench_energy.csv")
    depths = sorted({int(r["depth"]) for r in rows})
    by = {int(r["depth"]): r for r in rows}
    idle_w = float(rows[0]["idle_w"])
    load_w = float(rows[0]["load_w"])
    net_w = load_w - idle_w

    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{\textbf{Measured (this work).} X1 --- board-level energy "
                 r"per delegation-chain verification on the lab Pi 4, by chain depth. "
                 r"Sustained throughput is the mean over a 60\,s fixed-duration loop per "
                 r"depth; energy is the whole-board load--idle power delta ("
                 f"{load_w:.2f}\\,W load over a {idle_w:.2f}\\,W idle baseline, "
                 r"eyeball-read off an inline USB-C power meter, $\pm0.03$\,W read "
                 r"uncertainty) divided by throughput. Governor \texttt{ondemand} for "
                 r"this run (meter insertion power-cycles the board and does not persist "
                 r"the governor); clock held 1.8\,GHz throughout and per-depth latencies "
                 r"matched the \texttt{performance}-governor run within 0.5\%. The "
                 r"interval propagates the read uncertainty of both readings linearly "
                 r"($\pm0.06$\,W on the "
                 f"{net_w:.2f}\\,W delta, $\\pm{100 * POWER_UNC_W * 2 / net_w:.0f}\\%$). "
                 r"This is whole-board incremental energy, not the energy of the "
                 r"cryptographic operation alone.}")
    lines.append(r"\label{tab:bench-energy}")
    lines.append(r"\begin{tabular}{r r r r}")
    lines.append(r"\toprule")
    lines.append(r"Depth & Throughput (ops/s) & Energy/verify (mJ) & Energy/hop (mJ) \\")
    lines.append(r"\midrule")
    for d in depths:
        ops = float(by[d]["sustained_ops_per_s"])
        e_verify = net_w / ops * 1000.0  # W / (ops/s) = J/op; *1000 -> mJ
        e_hop = e_verify / d
        rel = 2 * POWER_UNC_W / net_w
        lines.append(f"{d} & {ops:.0f} & {_pm(e_verify, e_verify * rel)} & "
                     f"{_pm(e_hop, e_hop * rel)} " + r"\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# request trace: worked example of successive requests at one verifier
# ---------------------------------------------------------------------------
def make_trace_table() -> str:
    rows = read_csv("request_trace.csv")
    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Worked example: successive requests from one sensor at one "
                 r"fog verifier, as the reference implementation processes them "
                 r"(\texttt{request\_trace.py}). Depth-4 IoMT chain (the device sub-delegates "
                 r"to one sensor), effective caveats: "
                 r"topic \texttt{ward3/bed12/vitals/hr}, 12 exercises per minute. "
                 r"$t$ is verifier time in seconds after the first request; Ctr is the "
                 r"request counter. Every row, allow or deny, appends one evidence record; "
                 r"step~5 aggregates ten accepted requests. Before step~9 the verifier "
                 r"installs epoch~1, which revokes the gateway-to-device hop.}")
    lines.append(r"\label{tab:trace}")
    lines.append(r"\begin{tabular}{r r r l l l}")
    lines.append(r"\toprule")
    lines.append(r"Step & $t$ & Ctr & Signed by & Request & Verdict and reason \\")
    lines.append(r"\midrule")
    for r in rows:
        topic = r["topic"].replace("ward3/bed12/", "")
        req = r["note"] if r["note"] else "topic " + topic
        if r["note"] and topic != "vitals/hr":
            req = f"{r['note']}; topic {topic}"
        elif not r["note"]:
            req = "topic " + topic
        verdict = r["verdict"] + (f": {r['reason']}" if r["reason"] else "")
        verdict = verdict.replace("_", r"\_")
        t = str(r["t_s"]).replace("-", "--")
        c = str(r["counter"]).replace("-", "--")
        lines.append(f"{r['step']} & {t} & {c} & {r['signed_by']} & {req} & {verdict} " + r"\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def _pm(v: float, u: float) -> str:
    """Value and interval, the interval to one significant figure and the
    value to the same decimal place."""
    import math
    dec = max(0, -int(math.floor(math.log10(u))))
    u_r = round(u, dec)
    dec = max(0, -int(math.floor(math.log10(u_r))))
    return f"{v:.{dec}f} $\\pm$ {u_r:.{dec}f}"


if __name__ == "__main__":
    for name, fn in [
        ("trace_table.tex", make_trace_table),
        ("x4_table.tex", make_x4_table),
        ("x2_table.tex", make_x2_table),
        ("bench_table.tex", make_bench_table),
        ("bench_energy_table.tex", make_energy_table),
    ]:
        out = os.path.join(GEN, name)
        with open(out, "w") as f:
            f.write(fn())
        print(f"wrote {out}")
