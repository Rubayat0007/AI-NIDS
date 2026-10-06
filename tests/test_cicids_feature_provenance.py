from pathlib import Path

import pandas as pd

from src.features.schema import FEATURE_NAMES


RAW_DATA_DIR = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "raw"
    / "MachineLearningCVE"
)

RAW_FEATURE_COLUMNS = {
    "flow_duration": "Flow Duration",
    "total_fwd_packets": "Total Fwd Packets",
    "total_bwd_packets": "Total Backward Packets",
    "fwd_packet_length": "Fwd Packet Length Mean",
    "bwd_packet_length": "Bwd Packet Length Mean",
    "flow_rate": "Flow Bytes/s",
    "packet_rate": "Flow Packets/s",
    "avg_packet_size": "Average Packet Size",
    "syn_count": "SYN Flag Count",
    "ack_count": "ACK Flag Count",
    "rst_count": "RST Flag Count",
    "fin_count": "FIN Flag Count",
    "active_time": "Active Mean",
    "idle_time": "Idle Mean",
    "down_up_ratio": "Down/Up Ratio",
    "fwd_iat_mean": "Fwd IAT Mean",
    "bwd_iat_mean": "Bwd IAT Mean",
}

DERIVED_FEATURES = {
    "flow_bytes": (
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
    ),
    "flow_packets": (
        "Total Fwd Packets",
        "Total Backward Packets",
    ),
    "header_length": (
        "Fwd Header Length",
        "Bwd Header Length",
    ),
}


def test_cicids_schema_covers_all_model_features():
    csv_path = next(RAW_DATA_DIR.glob("*.csv"))
    columns = {
        column.strip()
        for column in pd.read_csv(csv_path, nrows=0).columns
    }

    for feature_name in FEATURE_NAMES:
        if feature_name in RAW_FEATURE_COLUMNS:
            assert RAW_FEATURE_COLUMNS[feature_name] in columns
        elif feature_name in DERIVED_FEATURES:
            assert all(
                source_column in columns
                for source_column in DERIVED_FEATURES[feature_name]
            )
        else:
            raise AssertionError(
                f"model feature has no CICIDS2017 provenance: {feature_name}"
            )


def test_model_feature_order_is_preserved():
    assert list(FEATURE_NAMES) == [
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
