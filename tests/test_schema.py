from src.features.schema import FEATURE_COUNT, FEATURE_NAMES


def test_feature_count():
    assert FEATURE_COUNT == 20


def test_feature_names_are_unique():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_feature_order_matches_cicids_training_order():
    expected = [
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "fwd_packet_length",
        "bwd_packet_length",
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
    ]

    assert FEATURE_NAMES == expected
