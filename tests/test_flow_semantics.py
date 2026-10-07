import math

import pytest

from scapy.all import IP, TCP, Raw

from src.features.flow import extract_flows
from src.features.model_input import features_to_model_input
from src.features.schema import FEATURE_NAMES


def test_deterministic_tcp_flow_matches_expected_model_semantics():
    packets = [
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(
                sport=12345,
                dport=80,
                flags="S",
                seq=1,
            )
            / Raw(b"1234567890")
        ),
        (
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(
                sport=80,
                dport=12345,
                flags="SA",
                seq=2,
                ack=2,
            )
            / Raw(b"abcdef")
        ),
        (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(
                sport=12345,
                dport=80,
                flags="A",
                seq=11,
                ack=3,
            )
            / Raw(b"abcdefgh")
        ),
    ]

    timestamps = [100.0, 100.001, 100.003]
    for packet, timestamp in zip(packets, timestamps):
        packet.time = timestamp

    flows = extract_flows(packets)

    assert len(flows) == 1

    features = flows[0]

    assert list(features) == FEATURE_NAMES

    assert math.isclose(features["flow_duration"], 3000.0, rel_tol=0.0, abs_tol=1e-9)
    assert features["total_fwd_packets"] == 2.0
    assert features["total_bwd_packets"] == 1.0

    assert features["fwd_packet_length"] == 9.0
    assert features["bwd_packet_length"] == 6.0

    assert features["flow_bytes"] == 24.0
    assert features["flow_packets"] == 3.0

    assert math.isclose(
        features["flow_rate"],
        8000.0,
        rel_tol=0.0,
        abs_tol=1e-9,
    )
    assert math.isclose(
        features["packet_rate"],
        1000.0,
        rel_tol=0.0,
        abs_tol=1e-9,
    )

    assert features["avg_packet_size"] == pytest.approx(34.0 / 3.0)

    assert features["syn_count"] == 2.0
    assert features["ack_count"] == 2.0
    assert features["rst_count"] == 0.0
    assert features["fin_count"] == 0.0

    assert math.isclose(features["active_time"], 3000.0, rel_tol=0.0, abs_tol=1e-9)
    assert features["idle_time"] == 0.0

    assert features["header_length"] > 0.0
    assert features["down_up_ratio"] == 0.0

    assert math.isclose(features["fwd_iat_mean"], 3000.0, rel_tol=0.0, abs_tol=1e-9)
    assert features["bwd_iat_mean"] == 0.0

    model_input = features_to_model_input(features)

    assert model_input.shape == (1, 20)
    assert model_input.dtype.kind == "f"

    assert all(math.isfinite(value) for value in model_input[0])
