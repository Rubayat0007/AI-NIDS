"""Export labelled flow features from a packet capture.

Produces the CSV that a live-domain validation set needs:

    flow_id,<20 canonical features>,label

``label`` is written empty - labelling is a human decision, and this tool
deliberately refuses to infer it. A companion check validates that a finished
file has usable labels before it is used for evaluation.

Exit codes: 0 success, 1 validation failure, 2 input/output error.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.flow import extract_flows  # noqa: E402
from src.features.schema import FEATURE_NAMES  # noqa: E402

LABELS = {"benign", "attack"}


def capture_duration(packets) -> float:
    if not packets:
        return 0.0
    times = [float(packet.time) for packet in packets]
    return max(0.0, max(times) - min(times))


def export(pcap: Path, output: Path) -> int:
    from scapy.all import rdpcap

    packets = rdpcap(str(pcap))

    if not packets:
        print(f"ERROR: no packets in {pcap}", file=sys.stderr)
        return 2

    flows = extract_flows(packets)

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["flow_id", *FEATURE_NAMES, "label"])
        writer.writeheader()

        for index, features in enumerate(flows):
            row = {name: features[name] for name in FEATURE_NAMES}
            row["flow_id"] = f"flow-{index:05d}"
            row["label"] = ""
            writer.writerow(row)

    print(
        f"packets={len(packets)} duration={capture_duration(packets):.3f}s "
        f"flows={len(flows)} -> {output}"
    )
    print("label column is empty by design; fill it before evaluation.")
    return 0


def validate(path: Path) -> int:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    problems = []

    if not reader.fieldnames or "label" not in reader.fieldnames:
        problems.append("missing label column")

    if not rows:
        problems.append("no rows")

    missing = [row.get("flow_id", "?") for row in rows if not (row.get("label") or "").strip()]
    if missing:
        problems.append(f"{len(missing)} unlabelled rows (first: {missing[0]})")

    invalid = sorted(
        {
            (row.get("label") or "").strip()
            for row in rows
            if (row.get("label") or "").strip() and (row.get("label") or "").strip() not in LABELS
        }
    )
    if invalid:
        problems.append(f"invalid labels: {invalid}")

    counts = {}
    for row in rows:
        label = (row.get("label") or "").strip()
        counts[label] = counts.get(label, 0) + 1

    print(f"rows={len(rows)} labels={counts}")

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)

    print("STATUS: PASS" if not problems else "STATUS: FAIL")
    return 0 if not problems else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, help="capture to export")
    parser.add_argument("--output", type=Path, help="CSV path to write")
    parser.add_argument("--validate", type=Path, help="check a labelled CSV")
    args = parser.parse_args()

    try:
        if args.validate:
            return validate(args.validate)

        if not args.pcap or not args.output:
            parser.error("either --validate or --pcap with --output is required")

        if not args.pcap.is_file():
            print(f"ERROR: pcap not found: {args.pcap}", file=sys.stderr)
            return 2

        return export(args.pcap, args.output)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
