"""Feature-parity audit: CICIDS2017 benign flows versus live benign flows.

Answers the first question behind the 0/75 live recall: do the 20 canonical
features mean the same thing in both worlds, and how far apart are their
distributions?

Method: sample benign rows from the processed CICIDS2017 CSV, capture real
benign flows from this host, then per feature report the two means, the
standardised difference, and the two-sample Kolmogorov-Smirnov statistic.

Caveats printed with the result: name-level parity only (the CICIDS columns
were produced by its own pipeline), one host and a short capture window, and
CICIDS benign is not a random sample of the internet.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scapy.all import conf, sniff  # noqa: E402
from scipy.stats import ks_2samp  # noqa: E402

from src.features.flow import extract_flows  # noqa: E402
from src.features.schema import FEATURE_NAMES  # noqa: E402

PROCESSED = PROJECT_ROOT / "data" / "processed" / "cicids2017_binary.csv"
SAMPLE_ROWS = 40_000
CAPTURE_SECONDS = 30.0


def cicids_benign_sample() -> pd.DataFrame:
    collected = []
    total = 0

    for chunk in pd.read_csv(PROCESSED, usecols=list(FEATURE_NAMES) + ["label"],
                             chunksize=200_000, low_memory=False):
        benign = chunk[chunk["label"].astype(str).str.strip().str.lower()
                       .isin(["0", "benign", "normal"])]
        if not benign.empty:
            collected.append(benign[list(FEATURE_NAMES)])
            total += len(benign)
        if total >= SAMPLE_ROWS:
            break

    if not collected:
        raise SystemExit("no benign rows found in the processed dataset")

    frame = pd.concat(collected, ignore_index=True).head(SAMPLE_ROWS)
    return frame.apply(pd.to_numeric, errors="coerce").dropna()


def capture_live_benign():
    interface = conf.route.route("0.0.0.0")[0]
    stop = threading.Event()

    def activity():
        hosts = ("pypi.org", "1.1.1.1", "8.8.8.8", "www.stratosphereips.org")
        while not stop.is_set():
            for host in hosts:
                try:
                    socket.getaddrinfo(host, 443)
                except Exception:
                    pass
                try:
                    urllib.request.urlopen("https://%s/" % host, timeout=5).read(256)
                except Exception:
                    pass
            time.sleep(0.2)

    threading.Thread(target=activity, daemon=True).start()
    try:
        packets = sniff(iface=interface, timeout=CAPTURE_SECONDS)
    finally:
        stop.set()

    flows = extract_flows(packets)
    live = pd.DataFrame([{name: float(flow[name]) for name in FEATURE_NAMES}
                         for flow in flows])
    return interface, len(packets), live


def verdict(ks: float) -> str:
    if ks < 0.2:
        return "small"
    if ks < 0.5:
        return "moderate"
    return "large"


def main() -> int:
    print("sampling CICIDS benign rows...")
    reference = cicids_benign_sample()
    print(f"CICIDS benign sample: {len(reference)} rows")

    print("capturing live benign flows...")
    interface, packet_count, live = capture_live_benign()
    print(f"interface: {interface} packets={packet_count} flows={len(live)}")

    if live.empty:
        raise SystemExit("no live flows captured")

    rows = []
    for name in FEATURE_NAMES:
        a = reference[name].to_numpy()
        b = live[name].to_numpy()
        ks, p_value = ks_2samp(a, b)

        pooled = np.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2.0) or 1.0
        standardised = abs(a.mean() - b.mean()) / pooled

        rows.append({
            "feature": name,
            "cicids_mean": float(a.mean()),
            "live_mean": float(b.mean()),
            "standardised_difference": round(float(standardised), 3),
            "ks_statistic": round(float(ks), 3),
            "ks_p_value": float(p_value),
            "verdict": verdict(float(ks)),
        })

    summary = {
        "cicids_rows": len(reference),
        "live_packets": packet_count,
        "live_flows": len(live),
        "interface": interface,
        "feature_verdicts": {row["feature"]: row["verdict"] for row in rows},
        "large_shift": [row["feature"] for row in rows if row["verdict"] == "large"],
        "small_shift": [row["feature"] for row in rows if row["verdict"] == "small"],
    }

    output_dir = PROJECT_ROOT / "results" / "feature_parity"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps({"summary": summary, "features": rows}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Feature-parity audit — CICIDS2017 benign vs live benign",
        "",
        f"Reference: {len(reference)} benign CICIDS2017 rows. "
        f"Live: {len(live)} flows from {packet_count} packets on `{interface}`, "
        f"{CAPTURE_SECONDS:.0f} s.",
        "",
        "| Feature | CICIDS mean | Live mean | Std diff | KS | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=lambda r: -r["ks_statistic"]):
        lines.append(
            f"| {row['feature']} | {row['cicids_mean']:.4g} | {row['live_mean']:.4g} | "
            f"{row['standardised_difference']:.2f} | {row['ks_statistic']:.2f} | {row['verdict']} |"
        )

    lines += [
        "",
        "## Reading this",
        "",
        f"- Large-shift features: {', '.join(summary['large_shift']) or 'none'}",
        f"- Small-shift features: {', '.join(summary['small_shift']) or 'none'}",
        "- A large KS statistic means the feature is distributed differently even"
        " for benign traffic; a model leaning on it will misjudge live flows.",
        "",
        "## Limits",
        "",
        "- Name-level parity only: the CICIDS columns come from its own flow"
        " pipeline, so identical names do not prove identical definitions.",
        "- One host, 30 seconds, mostly DNS and blocked HTTPS attempts — not a"
        " network population.",
        "- CICIDS benign is testbed traffic, not a random sample of the internet.",
        "- This does not by itself prove H1; it ranks which features are most"
        " likely to be mismatched and therefore worth checking definition-by-"
        " definition.",
    ]

    docs = PROJECT_ROOT / "docs" / "measurements"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "feature-parity-2026-10-24.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
