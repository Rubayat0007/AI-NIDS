"""Capture a labelled scenario on a real interface, ready for flow export.

For an isolated lab (two VMs or two machines on a host-only network), run one
capture per scenario:

    python scripts/lab_capture.py --scenario benign --seconds 600 --interface "Ethernet 2"
    python scripts/lab_capture.py --scenario scan   --seconds 120 --interface "Ethernet 2"

Each run writes a PCAP and appends a row to ``labels.csv`` with the scenario
label and the capture window, so flows can be attributed later without
guesswork. Loopback is deliberately excluded: it bypasses the real stack.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

LABEL_COLUMNS = ("scenario", "label", "start_epoch", "end_epoch", "pcap")


def label_row(scenario: str, label: int, start: float, end: float, pcap: str) -> dict:
    if label not in (0, 1):
        raise ValueError("label must be 0 (benign) or 1 (attack)")
    if end < start:
        raise ValueError("end must not precede start")

    return {
        "scenario": scenario,
        "label": int(label),
        "start_epoch": round(float(start), 3),
        "end_epoch": round(float(end), 3),
        "pcap": pcap,
    }


def append_labels(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.is_file()

    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(LABEL_COLUMNS))

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def real_interfaces():
    from scapy.all import get_if_list

    return [name for name in get_if_list() if "loopback" not in name.lower()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--label", type=int, choices=(0, 1), required=True,
                        help="0 = benign, 1 = attack")
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--interface", default=None,
                        help="interface name; required when several are present")
    parser.add_argument("--output-dir", type=Path,
                        default=PROJECT_ROOT / "data" / "lab_captures")
    args = parser.parse_args()

    from scapy.all import sniff, wrpcap

    candidates = real_interfaces()

    if args.interface is None:
        if len(candidates) != 1:
            print(f"ERROR: choose --interface; candidates: {candidates}", file=sys.stderr)
            return 2
        args.interface = candidates[0]

    if args.interface not in candidates:
        print(f"ERROR: {args.interface!r} is not a non-loopback interface: {candidates}",
              file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    pcap = args.output_dir / f"{args.scenario}_{int(time.time())}.pcap"

    print(f"capturing {args.seconds:.0f}s on {args.interface} -> {pcap}")
    started = time.time()
    packets = sniff(iface=args.interface, timeout=args.seconds)
    ended = time.time()

    if not packets:
        print("ERROR: no packets captured", file=sys.stderr)
        return 2

    wrpcap(str(pcap), packets)

    row = label_row(args.scenario, args.label, started, ended, pcap.name)
    append_labels(args.output_dir / "labels.csv", row)

    print(json.dumps({"packets": len(packets), **row}, sort_keys=True))
    print("next: export flows and validate before evaluating.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
