"""
Canonical feature schema for the CICIDS2017 NIDS model.

The order must remain identical to train_cicids2017.py.
"""

FEATURE_NAMES = [
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

FEATURE_COUNT = len(FEATURE_NAMES)
