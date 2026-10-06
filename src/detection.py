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
