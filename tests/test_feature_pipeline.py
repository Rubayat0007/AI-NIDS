import numpy as np
import pytest

from scapy.layers.inet import IP, TCP

from src.features.flow import extract_flows
from src.features.model_input import features_to_model_input
from src.features.schema import FEATURE_NAMES


def make_tcp_packet(
    src,
    dst,
    sport,
    dport,
    timestamp,
    payload,
    flags="A",
):
    packet = (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
        / payload
    )
    packet.time = timestamp
    return packet


def test_flow_features_integrate_with_model_input_adapter():
    packets = [
        make_tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            1000.0,
            b"a" * 6,
            flags="S",
        ),
        make_tcp_packet(
            "10.0.0.2",
            "10.0.0.1",
            80,
            12345,
            1000.001,
            b"b" * 6,
            flags="SA",
        ),
    ]

    flow_features = extract_flows(packets)

    assert len(flow_features) == 1
    assert list(flow_features[0]) == FEATURE_NAMES

    model_input = features_to_model_input(flow_features[0])

    assert isinstance(model_input, np.ndarray)
    assert model_input.shape == (1, len(FEATURE_NAMES))
    assert model_input.dtype == np.float64
    assert np.isfinite(model_input).all()

    for index, feature_name in enumerate(FEATURE_NAMES):
        assert model_input[0, index] == pytest.approx(
            float(flow_features[0][feature_name])
        )
