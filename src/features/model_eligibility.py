"""Model-eligibility rules for canonical flow features."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .schema import FEATURE_NAMES


def is_model_eligible_flow(features: Mapping[str, object]) -> bool:
    """Return whether a flow satisfies the frozen CICFlowMeter eligibility rule."""
    if not isinstance(features, Mapping):
        raise TypeError("features must be a mapping")

    actual_names = set(features)
    expected_names = set(FEATURE_NAMES)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names

    if missing:
        raise ValueError(f"missing flow features: {sorted(missing)}")

    if unexpected:
        raise ValueError(f"unexpected flow features: {sorted(unexpected)}")

    try:
        forward_packets = float(features["total_fwd_packets"])
        backward_packets = float(features["total_bwd_packets"])
    except (TypeError, ValueError) as exc:
        raise TypeError("flow packet counts must be numeric") from exc

    return forward_packets + backward_packets > 1.0


def filter_model_eligible_flows(
    flows: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Return only flows eligible for the frozen CICFlowMeter model boundary."""
    if not isinstance(flows, Sequence):
        raise TypeError("flows must be a sequence")

    return [
        flow
        for flow in flows
        if is_model_eligible_flow(flow)
    ]
