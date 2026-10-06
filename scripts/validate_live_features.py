"""Validate live packet capture and flow feature extraction without ML inference."""

from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.capture import capture_network_traffic
from src.features.flow import FEATURE_NAMES, extract_flows
from src.features.model_input import features_to_model_input


VALIDATION_SECONDS = 8.0


def validate_flow(features: Mapping[str, object], index: int) -> None:
    actual_names = list(features)

    if actual_names != FEATURE_NAMES:
        raise RuntimeError(
            f"flow {index}: feature schema mismatch: {actual_names}"
        )

    for name in FEATURE_NAMES:
        value = features[name]

        if isinstance(value, bool):
            raise RuntimeError(
                f"flow {index}: feature {name!r} is boolean"
            )

        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"flow {index}: feature {name!r} is not numeric"
            ) from exc

        if not math.isfinite(numeric_value):
            raise RuntimeError(
                f"flow {index}: feature {name!r} is not finite"
            )

    nonnegative_features = (
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "flow_bytes",
        "flow_packets",
        "flow_rate",
        "packet_rate",
        "avg_packet_size",
        "syn_count",
        "ack_count",
        "rst_count",
        "fin_count",
        "active_time",
        "idle_time",
        "header_length",
        "down_up_ratio",
        "fwd_iat_mean",
        "bwd_iat_mean",
    )

    for name in nonnegative_features:
        if float(features[name]) < 0.0:
            raise RuntimeError(
                f"flow {index}: feature {name!r} is negative"
            )

    packet_count = (
        float(features["total_fwd_packets"])
        + float(features["total_bwd_packets"])
    )

    if packet_count < 1.0:
        raise RuntimeError(
            f"flow {index}: packet count is invalid: {packet_count}"
        )

    model_input = features_to_model_input(features)

    if model_input.shape != (1, len(FEATURE_NAMES)):
        raise RuntimeError(
            f"flow {index}: unexpected model input shape: {model_input.shape}"
        )

    if not all(math.isfinite(float(value)) for value in model_input[0]):
        raise RuntimeError(
            f"flow {index}: model input contains non-finite values"
        )


def main() -> None:
    print(f"Capturing live traffic for {VALIDATION_SECONDS:g} seconds...")
    packets, elapsed = capture_network_traffic(VALIDATION_SECONDS)

    print(f"Captured packets: {len(packets)}")
    print(f"Elapsed seconds:  {elapsed:.3f}")

    if elapsed < 0.0 or not math.isfinite(elapsed):
        raise RuntimeError(f"invalid capture duration: {elapsed}")

    if not packets:
        raise RuntimeError(
            "No packets captured; feature validation cannot proceed."
        )

    flows = extract_flows(packets)

    print(f"Extracted flows:  {len(flows)}")

    if not flows:
        raise RuntimeError(
            "Packets were captured but no flows were extracted."
        )

    for index, features in enumerate(flows, start=1):
        validate_flow(features, index)

    print(f"Validated flows:  {len(flows)}")
    print("LIVE FEATURE VALIDATION: PASS")
    print("ML inference was not performed.")


if __name__ == "__main__":
    main()
