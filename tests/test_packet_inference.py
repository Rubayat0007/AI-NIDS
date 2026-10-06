import warnings

import numpy as np
from scapy.layers.inet import IP, TCP

from src.features.flow import extract_flows
from src.features.model_input import features_to_model_input
from src.features.schema import FEATURE_NAMES
from src.inference import load_model, predict_features


def make_packets():
    forward = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=12345, dport=443, flags="PA")
        / b"request"
    )
    backward = (
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=443, dport=12345, flags="PA")
        / b"response"
    )

    forward.time = 1_000_000.000
    backward.time = 1_000_000.001

    return [forward, backward]


def test_packets_to_frozen_model_inference():
    packets = make_packets()

    flows = extract_flows(packets)

    assert len(flows) == 1

    features = flows[0]

    assert list(features) == FEATURE_NAMES

    model_input = features_to_model_input(features)

    assert model_input.shape == (1, len(FEATURE_NAMES))
    assert np.isfinite(model_input).all()

    model = load_model()

    with warnings.catch_warnings():
        warnings.simplefilter("error")

        result = predict_features(model, features)

    assert result["prediction"] in {0, 1}

    probabilities = result["probabilities"]

    assert isinstance(probabilities, np.ndarray)
    assert probabilities.shape == (2,)
    assert np.isfinite(probabilities).all()
    assert float(probabilities.sum()) == 1.0
