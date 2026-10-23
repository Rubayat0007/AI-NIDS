"""Estimate false-positive rate on real benign traffic from this host.

Captures the active non-loopback interface for a short window while the host
makes ordinary outbound requests (DNS, TCP/TLS to a few hosts). Every flow is
benign by construction: this script generates no attack traffic.

This measures the false-positive side only. It says nothing about recall, and
a single host's traffic is not a network population.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import joblib  # noqa: E402
from scapy.all import conf, sniff  # noqa: E402

from src.features.flow import extract_flows  # noqa: E402
from src.features.schema import FEATURE_NAMES  # noqa: E402
from src.inference import load_model, predict_features  # noqa: E402


def benign_activity(stop: threading.Event):
    hosts = ("pypi.org", "www.stratosphereips.org", "mcfp.felk.cvut.cz",
             "1.1.1.1", "8.8.8.8")

    while not stop.is_set():
        for host in hosts:
            try:
                socket.getaddrinfo(host, 443)
            except Exception:
                pass
            try:
                urllib.request.urlopen(f"https://{host}/", timeout=5).read(256)
            except Exception:
                pass
            time.sleep(0.2)
        time.sleep(0.5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--output-dir", type=Path,
                        default=PROJECT_ROOT / "results" / "real_benign_fpr")
    parser.add_argument("--candidate", type=Path,
                        default=PROJECT_ROOT / "src" / "models" / "nids_live_candidate.pkl")
    args = parser.parse_args()

    interface = conf.route.route("0.0.0.0")[0]
    if "loopback" in interface.lower():
        print("ERROR: default route resolves to loopback; nothing to measure", file=sys.stderr)
        return 2

    print(f"interface: {interface} for {args.seconds:.0f}s")

    frozen = load_model()
    candidate = joblib.load(args.candidate) if args.candidate.is_file() else None

    stop = threading.Event()
    threading.Thread(target=benign_activity, args=(stop,), daemon=True).start()

    try:
        packets = sniff(iface=interface, timeout=args.seconds)
    finally:
        stop.set()

    flows = extract_flows(packets)
    print(f"packets={len(packets)} flows={len(flows)}")

    if not flows:
        print("ERROR: no flows captured", file=sys.stderr)
        return 2

    frozen_flags = 0
    candidate_flags = 0
    rows = []

    for features in flows:
        frozen_prediction = predict_features(frozen, features)["prediction"]
        frozen_flags += int(frozen_prediction)

        candidate_prediction = None
        if candidate is not None:
            vector = [[float(features[name]) for name in FEATURE_NAMES]]
            candidate_prediction = int(candidate.predict(vector)[0])
            candidate_flags += candidate_prediction

        rows.append({
            "frozen": int(frozen_prediction),
            "candidate": candidate_prediction,
        })

    summary = {
        "interface": interface,
        "seconds": args.seconds,
        "packets": len(packets),
        "flows": len(flows),
        "label": "benign by construction (no attack traffic generated)",
        "frozen": {
            "flagged": frozen_flags,
            "false_positive_rate": round(frozen_flags / len(flows), 4),
        },
        "candidate": None if candidate is None else {
            "flagged": candidate_flags,
            "false_positive_rate": round(candidate_flags / len(flows), 4),
        },
        "note": ("One host, short window, ordinary outbound traffic. Not a network "
                 "population and not a substitute for a labelled capture."),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
