"""Inspect representative live flows and their packet-level feature inputs."""

from __future__ import annotations

import math
from pathlib import Path
import sys

from scapy.layers.inet import IP, TCP, UDP


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.capture import capture_network_traffic
from src.features.flow import (
    FEATURE_NAMES,
    extract_flow_features,
    extract_flow_groups,
)
from src.features.model_eligibility import is_model_eligible_flow


CAPTURE_SECONDS = 8.0
MAX_FLOWS = 10


def packet_timestamp(packet: object) -> float | None:
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return None

    if not math.isfinite(timestamp):
        return None

    return timestamp


def packet_payload_length(packet: object) -> int:
    if TCP in packet:
        return len(bytes(packet[TCP].payload))

    if UDP in packet:
        return len(bytes(packet[UDP].payload))

    if IP in packet:
        return len(bytes(packet[IP].payload))

    return 0


def packet_header_length(packet: object) -> int:
    total = 0

    if IP in packet:
        total += int(packet[IP].ihl or 5) * 4

    if TCP in packet:
        total += int(packet[TCP].dataofs or 5) * 4
    elif UDP in packet:
        total += 8

    return total


def packet_endpoints(packet: object) -> tuple[str, int | None, str, int | None]:
    if IP not in packet:
        return ("?", None, "?", None)

    source = packet[IP].src
    destination = packet[IP].dst

    source_port = None
    destination_port = None

    if TCP in packet:
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
    elif UDP in packet:
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    return source, source_port, destination, destination_port


def packet_flags(packet: object) -> str:
    if TCP in packet:
        return str(packet[TCP].flags)

    if UDP in packet:
        return "UDP"

    return "OTHER"


def endpoint_text(endpoint: tuple[str, int | None]) -> str:
    host, port = endpoint

    if port is None:
        return host

    return f"{host}:{port}"


def packet_direction(
    packet: object,
    forward_endpoint: tuple[str, int | None],
) -> str:
    source, source_port, _, _ = packet_endpoints(packet)

    if (source, source_port) == forward_endpoint:
        return "FORWARD"

    return "BACKWARD"


def print_packet_details(
    packets: list[object],
    forward_endpoint: tuple[str, int | None],
) -> None:
    print("PACKET DETAILS")
    print("-" * 120)
    print(
        f"{'#':>3} "
        f"{'Time':>14} "
        f"{'Direction':>10} "
        f"{'Payload':>8} "
        f"{'Header':>8} "
        f"{'Flags':>8} "
        f"{'Source':>24} "
        f"{'Destination':>24}"
    )

    for index, packet in enumerate(packets, start=1):
        timestamp = packet_timestamp(packet)
        source, source_port, destination, destination_port = packet_endpoints(
            packet
        )

        source_text = endpoint_text((source, source_port))
        destination_text = endpoint_text((destination, destination_port))

        timestamp_text = (
            f"{timestamp:.6f}"
            if timestamp is not None
            else "N/A"
        )

        print(
            f"{index:>3} "
            f"{timestamp_text:>14} "
            f"{packet_direction(packet, forward_endpoint):>10} "
            f"{packet_payload_length(packet):>8} "
            f"{packet_header_length(packet):>8} "
            f"{packet_flags(packet):>8} "
            f"{source_text:>24} "
            f"{destination_text:>24}"
        )


def print_flow_features(features: dict[str, object]) -> None:
    print("CANONICAL FEATURES")
    print("-" * 100)

    for name in FEATURE_NAMES:
        print(f"{name:<22} {float(features[name]):.12g}")


def main() -> None:
    print(f"Capturing live traffic for {CAPTURE_SECONDS:g} seconds...")
    packets, elapsed = capture_network_traffic(CAPTURE_SECONDS)

    print(f"Captured packets: {len(packets)}")
    print(f"Elapsed seconds:  {elapsed:.3f}")

    if not packets:
        raise RuntimeError(
            "No packets captured; semantic inspection cannot proceed."
        )

    flow_groups = extract_flow_groups(packets)

    print(f"Extracted flow groups: {len(flow_groups)}")

    eligible_groups = []

    for group in flow_groups:
        features = extract_flow_features(group)

        if is_model_eligible_flow(features):
            eligible_groups.append((group, features))

    print(f"Model-eligible flows: {len(eligible_groups)}")
    print(
        f"Singleton flows excluded: "
        f"{len(flow_groups) - len(eligible_groups)}"
    )

    if not eligible_groups:
        raise RuntimeError(
            "No model-eligible flows captured; semantic inspection cannot proceed."
        )

    inspect_count = min(MAX_FLOWS, len(eligible_groups))

    print()
    print(f"Inspecting {inspect_count} model-eligible flows.")

    for flow_number, (group, features) in enumerate(
        eligible_groups[:MAX_FLOWS],
        start=1,
    ):
        flow_packets = group["packets"]
        forward_endpoint = group["forward_endpoint"]

        print()
        print("=" * 120)
        print(f"FLOW {flow_number}")
        print(
            "Forward endpoint: "
            f"{endpoint_text(forward_endpoint)}"
        )
        print(f"Packet count: {len(flow_packets)}")
        print()

        print_packet_details(flow_packets, forward_endpoint)
        print()

        print_flow_features(features)

    print()
    print("=" * 120)
    print("LIVE FLOW SEMANTIC INSPECTION COMPLETE")
    print("ML inference was not performed.")
    print("No model was loaded.")
    print("No extractor or dataset data was modified.")


if __name__ == "__main__":
    main()
