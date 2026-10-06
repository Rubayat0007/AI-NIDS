import pytest

from scapy.layers.inet import IP, TCP, UDP

from src.features.flow import (
    ACTIVITY_TIMEOUT_US,
    FLOW_TIMEOUT_US,
    extract_flow_features,
    extract_flows,
    group_packets_into_flows,
)
from src.features.schema import FEATURE_NAMES


def make_tcp_packet(
    src,
    dst,
    sport,
    dport,
    timestamp,
    payload=b"1234567890",
    flags="A",
):
    packet = (
        IP(src=src, dst=dst)
        / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
        )
        / payload
    )
    packet.time = timestamp
    return packet


def test_flow_grouping_is_bidirectional():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1.0,
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            1.5,
        ),
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            2.0,
        ),
    ]

    flows = group_packets_into_flows(packets)

    assert len(flows) == 1
    assert len(flows[0]["packets"]) == 3


def test_feature_vector_matches_canonical_schema():
    packet = make_tcp_packet(
        "10.0.0.1",
        "10.0.0.2",
        12345,
        80,
        1.0,
    )

    features = extract_flows([packet])

    assert len(features) == 1
    assert list(features[0]) == FEATURE_NAMES
    assert set(features[0]) == set(FEATURE_NAMES)


def test_packet_length_and_flow_bytes_use_payload_bytes():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1.0,
            payload=b"a" * 10,
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            1.5,
            payload=b"b" * 30,
        ),
    ]

    features = extract_flows(packets)[0]

    assert features["total_fwd_packets"] == 1.0
    assert features["total_bwd_packets"] == 1.0
    assert features["fwd_packet_length"] == pytest.approx(10.0)
    assert features["bwd_packet_length"] == pytest.approx(30.0)
    assert features["flow_bytes"] == pytest.approx(40.0)
    assert features["avg_packet_size"] == pytest.approx(20.0)


def test_directional_iat_is_calculated_separately():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1.0,
        ),
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1.2,
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            2.0,
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            2.4,
        ),
    ]

    features = extract_flows(packets)[0]

    assert features["fwd_iat_mean"] == pytest.approx(
        200_000.0
    )
    assert features["bwd_iat_mean"] == pytest.approx(
        400_000.0
    )


def test_header_length_uses_actual_headers():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1.0,
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            1.5,
        ),
    ]

    features = extract_flows(packets)[0]

    expected_header_length = sum(
        len(packet[IP]) - len(packet[IP].payload)
        + len(packet[TCP]) - len(packet[TCP].payload)
        for packet in packets
    )

    assert features["header_length"] == pytest.approx(
        expected_header_length
    )


def test_active_idle_use_activity_timeout_and_means():
    timestamps = [
        0.0,
        1.0,
        2.0,
        8.0,
        9.0,
    ]

    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            timestamp,
        )
        for timestamp in timestamps
    ]

    features = extract_flows(packets)[0]

    assert ACTIVITY_TIMEOUT_US == 5_000_000.0
    assert features["active_time"] == pytest.approx(
        1_500_000.0
    )
    assert features["idle_time"] == pytest.approx(
        6_000_000.0
    )


def test_flow_timeout_splits_long_flows():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            0.0,
        ),
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            10.0,
        ),
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            130.0,
        ),
    ]

    flows = group_packets_into_flows(
        packets,
        flow_timeout_us=FLOW_TIMEOUT_US,
    )

    assert len(flows) == 2
    assert len(flows[0]["packets"]) == 2
    assert len(flows[1]["packets"]) == 1


def test_empty_flow_returns_zero_schema():
    features = extract_flow_features(
        {
            "packets": [],
            "forward_endpoint": ("", 0),
        }
    )

    assert list(features) == FEATURE_NAMES
    assert all(
        value == 0.0
        for value in features.values()
    )


def test_udp_flow_is_supported():
    packet = (
        IP(
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        / UDP(
            sport=5000,
            dport=53,
        )
        / b"query"
    )

    packet.time = 1.0

    features = extract_flows([packet])

    assert len(features) == 1
    assert features[0]["total_fwd_packets"] == 1.0
    assert features[0]["total_bwd_packets"] == 0.0
    assert features[0]["flow_bytes"] == 5.0
