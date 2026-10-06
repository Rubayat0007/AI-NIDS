import pytest

from src.features.model_eligibility import (
    filter_model_eligible_flows,
    is_model_eligible_flow,
)
from src.features.schema import FEATURE_NAMES


def make_flow(forward_packets, backward_packets):
    features = {name: 0.0 for name in FEATURE_NAMES}
    features["total_fwd_packets"] = float(forward_packets)
    features["total_bwd_packets"] = float(backward_packets)
    return features


def test_single_packet_flow_is_not_model_eligible():
    flow = make_flow(1, 0)

    assert is_model_eligible_flow(flow) is False


def test_two_packet_bidirectional_flow_is_model_eligible():
    flow = make_flow(1, 1)

    assert is_model_eligible_flow(flow) is True


def test_two_packet_unidirectional_flow_is_model_eligible():
    flow = make_flow(2, 0)

    assert is_model_eligible_flow(flow) is True


def test_filter_removes_only_single_packet_flows():
    singleton = make_flow(1, 0)
    bidirectional = make_flow(1, 1)
    forward_only = make_flow(3, 0)

    result = filter_model_eligible_flows(
        [singleton, bidirectional, forward_only]
    )

    assert result == [bidirectional, forward_only]


def test_missing_feature_is_rejected():
    flow = make_flow(1, 1)
    del flow["flow_duration"]

    with pytest.raises(ValueError, match="missing flow features"):
        is_model_eligible_flow(flow)


def test_unexpected_feature_is_rejected():
    flow = make_flow(1, 1)
    flow["unexpected"] = 0.0

    with pytest.raises(ValueError, match="unexpected flow features"):
        is_model_eligible_flow(flow)


def test_non_numeric_packet_count_is_rejected():
    flow = make_flow(1, 1)
    flow["total_fwd_packets"] = "invalid"

    with pytest.raises(TypeError, match="packet counts must be numeric"):
        is_model_eligible_flow(flow)


def test_non_sequence_flows_are_rejected():
    with pytest.raises(TypeError, match="flows must be a sequence"):
        filter_model_eligible_flows(None)
