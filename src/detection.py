"""Packet-to-detection orchestration for the frozen NIDS model."""

from collections.abc import Sequence

import numpy as np

from .features.flow import extract_flows
from .inference import predict_features


def detect_packets(model, packets: Sequence, capture_duration: float):
    """Run frozen-model inference independently on each extracted flow."""
    try:
        capture_duration = float(capture_duration)
    except (TypeError, ValueError) as exc:
        raise TypeError("capture_duration must be numeric") from exc

    if not np.isfinite(capture_duration):
        raise ValueError("capture_duration must be finite")

    if capture_duration < 0:
        raise ValueError("capture_duration must be non-negative")

    flows = extract_flows(packets)

    results = []

    for features in flows:
        inference = predict_features(model, features)

        packet_count = int(
            features["total_fwd_packets"]
            + features["total_bwd_packets"]
        )

        results.append(
            {
                "prediction": inference["prediction"],
                "probabilities": inference["probabilities"],
                "features": features,
                "packet_count": packet_count,
                "flow_duration": float(features["flow_duration"]),
            }
        )

    return {
        "flows": results,
        "packet_count": len(packets),
        "capture_duration": capture_duration,
    }


def aggregate_detection_results(detection):
    """Aggregate per-flow results into the dashboard result contract."""
    if not isinstance(detection, dict):
        raise TypeError("detection must be a mapping")

    flows = detection.get("flows")

    if not isinstance(flows, list):
        raise TypeError("detection['flows'] must be a list")

    packet_count = detection.get("packet_count")
    capture_duration = detection.get("capture_duration")

    if isinstance(packet_count, bool):
        raise TypeError("packet_count must be an integer")

    try:
        numeric_packet_count = float(packet_count)
    except (TypeError, ValueError) as exc:
        raise TypeError("packet_count must be an integer") from exc

    if not np.isfinite(numeric_packet_count):
        raise ValueError("packet_count must be an integer")

    if not numeric_packet_count.is_integer():
        raise ValueError("packet_count must be an integer")

    packet_count = int(numeric_packet_count)

    try:
        capture_duration = float(capture_duration)
    except (TypeError, ValueError) as exc:
        raise TypeError("capture_duration must be numeric") from exc

    if packet_count < 0:
        raise ValueError("packet_count must be non-negative")

    if not np.isfinite(capture_duration) or capture_duration < 0:
        raise ValueError(
            "capture_duration must be finite and non-negative"
        )

    if not flows:
        return {
            "prediction": 0,
            "confidence": 0.0,
            "attack_probability": 0.0,
            "severity": "LOW",
            "packet_count": packet_count,
            "duration": capture_duration,
            "flows": [],
        }

    for flow in flows:
        if not isinstance(flow, dict):
            raise TypeError("each flow result must be a mapping")

        if "prediction" not in flow or "probabilities" not in flow:
            raise ValueError(
                "each flow result must contain prediction and probabilities"
            )

        probabilities = np.asarray(flow["probabilities"], dtype=float)

        if probabilities.shape != (2,):
            raise ValueError(
                "each flow probability vector must have shape (2,)"
            )

        if not np.isfinite(probabilities).all():
            raise ValueError(
                "flow probabilities must be finite"
            )

        if not np.isclose(float(probabilities.sum()), 1.0):
            raise ValueError(
                "flow probabilities must sum to 1"
            )

        prediction = int(flow["prediction"])

        if prediction not in {0, 1}:
            raise ValueError(
                "flow prediction must be 0 or 1"
            )

    selected_flow = max(
        flows,
        key=lambda flow: float(
            np.asarray(flow["probabilities"], dtype=float)[1]
        ),
    )

    selected_probabilities = np.asarray(
        selected_flow["probabilities"],
        dtype=float,
    )

    attack_probability = float(selected_probabilities[1])
    confidence = float(selected_probabilities.max())
    prediction = int(
        any(int(flow["prediction"]) == 1 for flow in flows)
    )

    if prediction == 1:
        if confidence >= 0.80:
            severity = "HIGH"
        elif confidence >= 0.50:
            severity = "MEDIUM"
        else:
            severity = "SUSPICIOUS"
    elif confidence < 0.75:
        severity = "SUSPICIOUS"
    else:
        severity = "LOW"

    return {
        "prediction": prediction,
        "confidence": confidence,
        "attack_probability": attack_probability,
        "severity": severity,
        "packet_count": packet_count,
        "duration": capture_duration,
        "flows": flows,
    }
