"""Analyze held-out errors by original CICIDS2017 source label and file."""

from pathlib import Path
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.schema import FEATURE_NAMES
from src.inference import load_model

PROCESSED_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_binary.csv"
)
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "MachineLearningCVE"

RANDOM_STATE = 42
TEST_SIZE = 0.20

SOURCE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "Active Mean",
    "Idle Mean",
    "Down/Up Ratio",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Header Length",
    "Bwd Header Length",
    "Label",
]

DIRECT_MAPPING = {
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

ATTACK_LABELS = {
    "BENIGN": "BENIGN",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS slowloris": "DoS slowloris",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "DoS Hulk": "DoS Hulk",
    "DoS GoldenEye": "DoS GoldenEye",
    "Heartbleed": "Heartbleed",
    "Web Attack ? Brute Force": "Web Attack - Brute Force",
    "Web Attack ? XSS": "Web Attack - XSS",
    "Web Attack ? Sql Injection": "Web Attack - Sql Injection",
    "Infiltration": "Infiltration",
    "Bot": "Bot",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
}


def normalize_label(value):
    text = str(value).strip()
    if text == "BENIGN":
        return 0
    return 1


def prepare_source_frame(path):
    frame = pd.read_csv(
        path,
        usecols=SOURCE_COLUMNS,
        skipinitialspace=True,
        low_memory=False,
    )
    frame.columns = frame.columns.str.strip()

    frame["flow_bytes"] = (
        frame["Total Length of Fwd Packets"]
        + frame["Total Length of Bwd Packets"]
    )
    frame["flow_packets"] = (
        frame["Total Fwd Packets"]
        + frame["Total Backward Packets"]
    )
    frame["header_length"] = (
        frame["Fwd Header Length"]
        + frame["Bwd Header Length"]
    )

    for feature_name in FEATURE_NAMES:
        if feature_name in DIRECT_MAPPING:
            frame[feature_name] = frame[
                DIRECT_MAPPING[feature_name]
            ]

    for feature_name in FEATURE_NAMES:
        frame[feature_name] = pd.to_numeric(
            frame[feature_name],
            errors="coerce",
        )

    frame.replace([np.inf, -np.inf], np.nan, inplace=True)
    frame.dropna(subset=FEATURE_NAMES, inplace=True)

    for feature_name in [
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "flow_bytes",
        "flow_packets",
    ]:
        frame = frame[frame[feature_name] >= 0]

    labels = frame["Label"].astype(str).str.strip().str.upper()
    frame["binary_label"] = (labels != "BENIGN").astype("int8")
    frame["source_label"] = frame["Label"].astype(str).str.strip()
    frame["source_file"] = path.name

    return frame[
        FEATURE_NAMES
        + [
            "binary_label",
            "source_label",
            "source_file",
        ]
    ]


def build_source_provenance():
    frames = []

    for path in sorted(RAW_DIR.glob("*.csv")):
        print(f"Processing source: {path.name}")
        frames.append(prepare_source_frame(path))

    combined = pd.concat(frames, ignore_index=True)

    # Match prepare_cicids2017.py: deduplicate on model features and label
    # before float32 casting. Provenance columns are intentionally excluded.
    combined = combined.drop_duplicates(
        subset=FEATURE_NAMES + ["binary_label"],
        keep="first",
    )

    combined[FEATURE_NAMES] = combined[FEATURE_NAMES].astype(
        "float32"
    )

    return combined.reset_index(drop=True)


def main():
    if not PROCESSED_PATH.is_file():
        raise FileNotFoundError(
            f"Processed dataset not found: {PROCESSED_PATH}"
        )

    if not RAW_DIR.is_dir():
        raise FileNotFoundError(
            f"Raw CICIDS2017 directory not found: {RAW_DIR}"
        )

    frozen = pd.read_csv(PROCESSED_PATH)

    if list(frozen[FEATURE_NAMES]) != FEATURE_NAMES:
        raise RuntimeError(
            "Frozen dataset feature order does not match the canonical schema."
        )

    X = frozen[FEATURE_NAMES].replace(
        [np.inf, -np.inf],
        np.nan,
    )
    valid = X.notna().all(axis=1)

    X = X.loc[valid].copy()
    y = frozen.loc[valid, "label"].astype(int)

    train_indices, test_indices = train_test_split(
        np.arange(len(X)),
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    test_X = X.iloc[test_indices]
    test_y = y.iloc[test_indices]

    model = load_model()
    predictions = model.predict(test_X)

    errors = pd.DataFrame(
        {
            "actual": test_y.to_numpy(),
            "prediction": predictions.astype(int),
        },
        index=test_X.index,
    )

    errors["error_type"] = np.where(
        (errors["actual"] == 0) & (errors["prediction"] == 1),
        "FALSE_POSITIVE",
        np.where(
            (errors["actual"] == 1) & (errors["prediction"] == 0),
            "FALSE_NEGATIVE",
            "CORRECT",
        ),
    )

    provenance = build_source_provenance()

    if len(provenance) != len(frozen):
        raise RuntimeError(
            "Source provenance row count does not match the frozen dataset: "
            f"{len(provenance)} != {len(frozen)}"
        )

    frozen_features = frozen[FEATURE_NAMES].to_numpy(
        dtype="float32"
    )
    provenance_features = provenance[FEATURE_NAMES].to_numpy(
        dtype="float32"
    )

    if not np.array_equal(
        frozen_features,
        provenance_features,
    ):
        mismatch = np.any(
            frozen_features != provenance_features,
            axis=1,
        )
        first_mismatch = int(np.flatnonzero(mismatch)[0])
        raise RuntimeError(
            "Source provenance feature rows do not match the frozen "
            "dataset at row "
            f"{first_mismatch}."
        )

    frozen_labels = frozen["label"].to_numpy(
        dtype="int8"
    )
    provenance_labels = provenance["binary_label"].to_numpy(
        dtype="int8"
    )

    if not np.array_equal(
        frozen_labels,
        provenance_labels,
    ):
        mismatch = frozen_labels != provenance_labels
        first_mismatch = int(np.flatnonzero(mismatch)[0])
        raise RuntimeError(
            "Source provenance labels do not match the frozen "
            "dataset at row "
            f"{first_mismatch}."
        )

    print("Source provenance alignment: exact row-for-row match.")

    provenance = provenance.iloc[test_X.index].copy()
    provenance["actual"] = errors["actual"].to_numpy()
    provenance["prediction"] = errors["prediction"].to_numpy()
    provenance["error_type"] = errors["error_type"].to_numpy()

    error_rows = provenance[
        provenance["error_type"] != "CORRECT"
    ].copy()

    print()
    print("=== Held-Out Error Provenance ===")
    print(f"Frozen rows:       {len(frozen):,}")
    print(f"Held-out rows:     {len(test_X):,}")
    print(f"Error rows:        {len(error_rows):,}")
    print()

    print("=== Error Type ===")
    print(
        error_rows["error_type"]
        .value_counts()
        .to_string()
    )
    print()

    print("=== Errors by Original CICIDS2017 Label ===")
    label_table = (
        error_rows
        .groupby(["error_type", "source_label"])
        .size()
        .reset_index(name="errors")
        .sort_values(
            ["error_type", "errors"],
            ascending=[True, False],
        )
    )

    if label_table.empty:
        print("No held-out errors found.")
    else:
        print(label_table.to_string(index=False))

    print()
    print("=== Errors by Source File ===")
    file_table = (
        error_rows
        .groupby(["error_type", "source_file"])
        .size()
        .reset_index(name="errors")
        .sort_values(
            ["error_type", "errors"],
            ascending=[True, False],
        )
    )

    if file_table.empty:
        print("No held-out errors found.")
    else:
        print(file_table.to_string(index=False))

    print()
    print("=== Attack Recall by Original Attack Label ===")

    attack_rows = provenance[
        provenance["actual"] == 1
    ].copy()

    attack_summary = (
        attack_rows
        .groupby("source_label")
        .agg(
            rows=("actual", "size"),
            false_negatives=(
                "error_type",
                lambda values: int(
                    (values == "FALSE_NEGATIVE").sum()
                ),
            ),
        )
        .reset_index()
    )

    attack_summary["recall"] = (
        1.0
        - attack_summary["false_negatives"]
        / attack_summary["rows"]
    )

    attack_summary = attack_summary.sort_values(
        ["recall", "rows"],
        ascending=[True, False],
    )

    if attack_summary.empty:
        print("No attack rows found.")
    else:
        print(
            attack_summary.to_string(
                index=False,
                formatters={
                    "recall": lambda value: f"{value:.4%}",
                },
            )
        )

    print()
    print(
        "This is supplementary provenance analysis of the fixed "
        "held-out split. It does not modify the dataset, model, "
        "training procedure, or primary benchmark."
    )


if __name__ == "__main__":
    main()