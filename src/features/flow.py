from collections import defaultdict
from typing import Iterable

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .schema import FEATURE_NAMES


FLOW_TIMEOUT_US = 120_000_000.0
ACTIVITY_TIMEOUT_US = 5_000_000.0


def _safe_float(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    if not np.isfinite(value):
        return 0.0

    return value


def _packet_timestamp(packet):
    try:
        return _safe_float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return 0.0


def _payload_length(packet):
    if TCP in packet:
        return float(len(bytes(packet[TCP].payload)))
    if UDP in packet:
        return float(len(bytes(packet[UDP].payload)))
    if IP in packet:
        return float(len(bytes(packet[IP].payload)))
    return 0.0


def _packet_header_length(packet):
    if IP not in packet:
        return 0.0

    ip = packet[IP]
    ip_header_length = int(ip.ihl or 5) * 4

    if TCP in packet:
        transport_header_length = int(packet[TCP].dataofs or 5) * 4
    elif UDP in packet:
        transport_header_length = 8
    else:
        transport_header_length = 0

    return float(ip_header_length + transport_header_length)


def _transport_ports(packet):
    if TCP in packet:
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return 0, 0


def _protocol_name(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    return str(packet[IP].proto)


def _flow_key(packet):
    if IP not in packet:
        return None

    src_port, dst_port = _transport_ports(packet)
    protocol = _protocol_name(packet)

    endpoints = (
        (packet[IP].src, src_port),
        (packet[IP].dst, dst_port),
    )

    ordered = tuple(sorted(endpoints))

    return (
        protocol,
        ordered[0],
        ordered[1],
    )


def _tcp_flag_counts(packet):
    counts = {
        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
    }

    if TCP not in packet:
        return counts

    flags = int(packet[TCP].flags)

    counts["syn_count"] = int(bool(flags & 0x02))
    counts["ack_count"] = int(bool(flags & 0x10))
    counts["rst_count"] = int(bool(flags & 0x04))
    counts["fin_count"] = int(bool(flags & 0x01))

    return counts


def _mean_iat(timestamps):
    if len(timestamps) < 2:
        return 0.0

    timestamps = sorted(timestamps)
    intervals = np.diff(timestamps) * 1_000_000.0

    if len(intervals) == 0:
        return 0.0

    return _safe_float(np.mean(intervals))


def _active_idle_means(timestamps):
    if len(timestamps) < 2:
        return 0.0, 0.0

    timestamps = sorted(timestamps)

    active_periods = []
    idle_periods = []

    start_active = timestamps[0]
    end_active = timestamps[0]

    for timestamp in timestamps[1:]:
        gap_us = (timestamp - end_active) * 1_000_000.0

        if gap_us > ACTIVITY_TIMEOUT_US:
            active_duration = (
                end_active - start_active
            ) * 1_000_000.0

            if active_duration > 0:
                active_periods.append(active_duration)

            idle_periods.append(gap_us)

            start_active = timestamp
            end_active = timestamp
        else:
            end_active = timestamp

    final_active = (
        end_active - start_active
    ) * 1_000_000.0

    if final_active > 0:
        active_periods.append(final_active)

    active_mean = (
        float(np.mean(active_periods))
        if active_periods
        else 0.0
    )

    idle_mean = (
        float(np.mean(idle_periods))
        if idle_periods
        else 0.0
    )

    return (
        _safe_float(active_mean),
        _safe_float(idle_mean),
    )


def group_packets_into_flows(
    packets: Iterable[Packet],
    flow_timeout_us=FLOW_TIMEOUT_US,
):
    """
    Group packets into bidirectional flows.

    The first packet establishes the forward direction. A new flow is
    started when the elapsed time from the flow's first packet exceeds
    the CICFlowMeter flow-timeout boundary.
    """

    grouped = defaultdict(list)

    for packet in packets:
        key = _flow_key(packet)

        if key is not None:
            grouped[key].append(packet)

    flows = []

    for packets_for_key in grouped.values():
        packets_for_key.sort(key=_packet_timestamp)

        current_flow = []

        for packet in packets_for_key:
            if not current_flow:
                current_flow = [packet]
                continue

            start_time = _packet_timestamp(current_flow[0])
            current_time = _packet_timestamp(packet)
            elapsed_us = (
                current_time - start_time
            ) * 1_000_000.0

            if elapsed_us > flow_timeout_us:
                if len(current_flow) > 1:
                    flows.append(_build_flow(current_flow))

                current_flow = [packet]
            else:
                current_flow.append(packet)

        if len(current_flow) > 1:
            flows.append(_build_flow(current_flow))
        elif current_flow:
            flows.append(_build_flow(current_flow))

    return flows


def _build_flow(packets):
    first = packets[0]
    src_port, _ = _transport_ports(first)

    return {
        "packets": packets,
        "forward_endpoint": (
            first[IP].src,
            src_port,
        ),
    }


def extract_flow_features(flow):
    """
    Extract a 20-feature vector matching the frozen model schema.
    """

    packets = flow["packets"]
    forward_endpoint = flow["forward_endpoint"]

    if not packets:
        return {
            feature: 0.0
            for feature in FEATURE_NAMES
        }

    forward_lengths = []
    backward_lengths = []

    forward_timestamps = []
    backward_timestamps = []
    all_timestamps = []

    total_bytes = 0.0
    header_length = 0.0

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0

    for packet in packets:
        if IP not in packet:
            continue

        source_port, _ = _transport_ports(packet)
        endpoint = (
            packet[IP].src,
            source_port,
        )

        timestamp = _packet_timestamp(packet)
        payload_length = _payload_length(packet)

        all_timestamps.append(timestamp)
        total_bytes += payload_length
        header_length += _packet_header_length(packet)

        flags = _tcp_flag_counts(packet)
        syn_count += flags["syn_count"]
        ack_count += flags["ack_count"]
        rst_count += flags["rst_count"]
        fin_count += flags["fin_count"]

        if endpoint == forward_endpoint:
            forward_lengths.append(payload_length)
            forward_timestamps.append(timestamp)
        else:
            backward_lengths.append(payload_length)
            backward_timestamps.append(timestamp)

    packet_count = (
        len(forward_lengths)
        + len(backward_lengths)
    )

    if packet_count == 0:
        return {
            feature: 0.0
            for feature in FEATURE_NAMES
        }

    all_timestamps.sort()

    duration_us = (
        max(
            0.0,
            (
                all_timestamps[-1]
                - all_timestamps[0]
            )
            * 1_000_000.0,
        )
        if len(all_timestamps) >= 2
        else 0.0
    )

    forward_count = len(forward_lengths)
    backward_count = len(backward_lengths)

    forward_bytes = float(sum(forward_lengths))
    backward_bytes = float(sum(backward_lengths))

    fwd_packet_length = (
        forward_bytes / forward_count
        if forward_count
        else 0.0
    )

    bwd_packet_length = (
        backward_bytes / backward_count
        if backward_count
        else 0.0
    )

    avg_packet_size = (
        total_bytes / packet_count
    )

    duration_seconds = (
        duration_us / 1_000_000.0
    )

    flow_rate = (
        total_bytes / duration_seconds
        if duration_seconds > 0
        else 0.0
    )

    packet_rate = (
        packet_count / duration_seconds
        if duration_seconds > 0
        else 0.0
    )

    down_up_ratio = (
        backward_count / forward_count
        if forward_count
        else 0.0
    )

    active_time, idle_time = _active_idle_means(
        all_timestamps
    )

    features = {
        "flow_duration": duration_us,
        "total_fwd_packets": float(forward_count),
        "total_bwd_packets": float(backward_count),
        "fwd_packet_length": fwd_packet_length,
        "bwd_packet_length": bwd_packet_length,
        "flow_bytes": total_bytes,
        "flow_packets": float(packet_count),
        "flow_rate": flow_rate,
        "packet_rate": packet_rate,
        "avg_packet_size": avg_packet_size,
        "syn_count": float(syn_count),
        "ack_count": float(ack_count),
        "rst_count": float(rst_count),
        "fin_count": float(fin_count),
        "active_time": active_time,
        "idle_time": idle_time,
        "header_length": header_length,
        "down_up_ratio": down_up_ratio,
        "fwd_iat_mean": _mean_iat(
            forward_timestamps
        ),
        "bwd_iat_mean": _mean_iat(
            backward_timestamps
        ),
    }

    return {
        feature: _safe_float(
            features.get(feature, 0.0)
        )
        for feature in FEATURE_NAMES
    }


def extract_flows(packets: Iterable[Packet]):
    """
    Extract one canonical feature vector for every
    observed bidirectional flow.
    """

    return [
        extract_flow_features(flow)
        for flow in group_packets_into_flows(packets)
    ]
