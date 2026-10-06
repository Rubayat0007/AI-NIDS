import warnings

import numpy as np
import pytest
from scapy.layers.inet import IP, TCP

from src.detection import (
    aggregate_detection_results,
    detect_packets,
)
from src.features.schema import FEATURE_NAMES
from src.inference import load_model


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


def test_detect_packets_returns_one_result_per_flow():
    model = load_model()

    with warnings.catch_warnings():
        warnings.simplefilter("error")

        result = detect_packets(
            model,
            make_packets(),
            capture_duration=8.0,
        )

    assert result["packet_count"] == 2
    assert result["capture_duration"] == 8.0
    assert len(result["flows"]) == 1

    flow_result = result["flows"][0]

    assert flow_result["prediction"] in {0, 1}
    assert flow_result["packet_count"] == 2
    assert flow_result["flow_duration"] == pytest.approx(1000.0)

    assert list(flow_result["features"]) == FEATURE_NAMES

    probabilities = flow_result["probabilities"]

    assert isinstance(probabilities, np.ndarray)
    assert probabilities.shape == (2,)
    assert np.isfinite(probabilities).all()
    assert float(probabilities.sum()) == pytest.approx(1.0)


def test_detect_packets_preserves_multiple_flow_boundaries():
    model = load_model()

    first = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=12345, dport=443, flags="PA")
        / b"first"
    )
    second = (
        IP(src="192.0.2.30", dst="198.51.100.40")
        / TCP(sport=23456, dport=443, flags="PA")
        / b"second"
    )

    first.time = 1_000_000.000
    second.time = 1_000_000.100

    with warnings.catch_warnings():
        warnings.simplefilter("error")

        result = detect_packets(
            model,
            [first, second],
            capture_duration=8.0,
        )

    assert result["packet_count"] == 2
    assert len(result["flows"]) == 2
    assert [flow["packet_count"] for flow in result["flows"]] == [1, 1]


def test_detect_packets_allows_empty_packet_capture():
    model = load_model()

    result = detect_packets(
        model,
        [],
        capture_duration=8.0,
    )

    assert result == {
        "flows": [],
        "packet_count": 0,
        "capture_duration": 8.0,
    }


@pytest.mark.parametrize(
    "capture_duration",
    [
        float("nan"),
        float("inf"),
        -1.0,
        "not-a-duration",
    ],
)
def test_detect_packets_rejects_invalid_capture_duration(
    capture_duration,
):
    model = load_model()

    with pytest.raises((TypeError, ValueError)):
        detect_packets(
            model,
            [],
            capture_duration=capture_duration,
        )



def test_aggregate_detection_results_selects_highest_attack_probability():
    detection = {
        "flows": [
            {
                "prediction": 0,
                "probabilities": np.array([0.90, 0.10]),
            },
            {
                "prediction": 1,
                "probabilities": np.array([0.15, 0.85]),
            },
        ],
        "packet_count": 4,
        "capture_duration": 8.0,
    }

    result = aggregate_detection_results(detection)

    assert result["prediction"] == 1
    assert result["attack_probability"] == pytest.approx(0.85)
    assert result["confidence"] == pytest.approx(0.85)
    assert result["severity"] == "HIGH"
    assert result["packet_count"] == 4
    assert result["duration"] == 8.0
    assert result["flows"] is detection["flows"]


def test_aggregate_detection_results_uses_highest_risk_flow_when_all_benign():
    detection = {
        "flows": [
            {
                "prediction": 0,
                "probabilities": np.array([0.95, 0.05]),
            },
            {
                "prediction": 0,
                "probabilities": np.array([0.60, 0.40]),
            },
        ],
        "packet_count": 4,
        "capture_duration": 8.0,
    }

    result = aggregate_detection_results(detection)

    assert result["prediction"] == 0
    assert result["attack_probability"] == pytest.approx(0.40)
    assert result["confidence"] == pytest.approx(0.60)
    assert result["severity"] == "SUSPICIOUS"


def test_aggregate_detection_results_handles_empty_detection():
    detection = {
        "flows": [],
        "packet_count": 0,
        "capture_duration": 8.0,
    }

    result = aggregate_detection_results(detection)

    assert result == {
        "prediction": 0,
        "confidence": 0.0,
        "attack_probability": 0.0,
        "severity": "LOW",
        "packet_count": 0,
        "duration": 8.0,
        "flows": [],
    }


@pytest.mark.parametrize(
    "invalid_detection",
    [
        None,
        {"flows": "invalid", "packet_count": 0, "capture_duration": 8.0},
        {"flows": [{}], "packet_count": 1, "capture_duration": 8.0},
        {
            "flows": [
                {
                    "prediction": 0,
                    "probabilities": np.array([0.8, 0.1]),
                }
            ],
            "packet_count": 1,
            "capture_duration": 8.0,
        },
    ],
)
def test_aggregate_detection_results_rejects_invalid_contract(
    invalid_detection,
):
    with pytest.raises((TypeError, ValueError)):
        aggregate_detection_results(invalid_detection)

@pytest.mark.parametrize("packet_count", [1.5, float("nan"), float("inf")])
def test_aggregate_detection_results_rejects_non_integer_packet_count(
    packet_count,
):
    detection = {
        "flows": [],
        "packet_count": packet_count,
        "capture_duration": 8.0,
    }

    with pytest.raises((TypeError, ValueError)):
        aggregate_detection_results(detection)
