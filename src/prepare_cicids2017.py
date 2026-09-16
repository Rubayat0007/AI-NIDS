from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "MachineLearningCVE"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_FILE = PROCESSED_DIR / "cicids2017_binary.csv"


MODEL_FEATURES = [
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


DERIVED_SOURCE_COLUMNS = {
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Header Length",
    "Bwd Header Length",
}


SOURCE_COLUMNS = sorted(
    set(DIRECT_MAPPING.values())
    | DERIVED_SOURCE_COLUMNS
    | {"Label"}
)


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(column).strip() for column in df.columns]
    return df


def process_file(csv_file: Path) -> pd.DataFrame:
    print(f"Reading: {csv_file.name}")

    df = pd.read_csv(
        csv_file,
        usecols=SOURCE_COLUMNS,
        skipinitialspace=True,
        low_memory=False,
    )

    df = clean_column_names(df)

    # Derived features required by the original model.
    df["flow_bytes"] = (
        df["Total Length of Fwd Packets"]
        + df["Total Length of Bwd Packets"]
    )

    df["flow_packets"] = (
        df["Total Fwd Packets"]
        + df["Total Backward Packets"]
    )

    df["header_length"] = (
        df["Fwd Header Length"]
        + df["Bwd Header Length"]
    )

    # Rename the directly mapped CIC-IDS2017 columns.
    rename_mapping = {
        source_name: model_name
        for model_name, source_name in DIRECT_MAPPING.items()
    }

    df = df.rename(columns=rename_mapping)

    # Convert all model features to numeric values.
    for feature in MODEL_FEATURES:
        df[feature] = pd.to_numeric(
            df[feature],
            errors="coerce",
        )

    # Convert BENIGN to 0 and every attack category to 1.
    labels = df["Label"].astype(str).str.strip().str.upper()
    df["label"] = (labels != "BENIGN").astype("int8")

    # Replace invalid numerical values.
    df[MODEL_FEATURES] = df[MODEL_FEATURES].replace(
        [np.inf, -np.inf],
        np.nan,
    )

    df = df.dropna(subset=MODEL_FEATURES)

    # Remove physically invalid values from key network features.
    nonnegative_features = [
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "flow_bytes",
        "flow_packets",
    ]

    for feature in nonnegative_features:
        df = df[df[feature] >= 0]

    # Keep only the features expected by the trained model.
    result = df[MODEL_FEATURES + ["label"]].copy()

    print(
        f"  Rows kept: {len(result):,} | "
        f"Attacks: {int(result['label'].sum()):,}"
    )

    return result


def main() -> None:
    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"Raw dataset directory was not found: {RAW_DIR}"
        )

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in: {RAW_DIR}"
        )

    print(f"Found {len(csv_files)} CSV files.")

    processed_frames = []

    for csv_file in csv_files:
        processed_frames.append(process_file(csv_file))

    print("Combining processed files...")

    combined = pd.concat(
        processed_frames,
        ignore_index=True,
    )

    print("Removing duplicate rows...")
    combined = combined.drop_duplicates()

    combined[MODEL_FEATURES] = combined[MODEL_FEATURES].astype(
        "float32"
    )
    combined["label"] = combined["label"].astype("int8")

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    combined.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print()
    print("Preprocessing complete.")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Total rows: {len(combined):,}")
    print(f"Benign rows: {int((combined['label'] == 0).sum()):,}")
    print(f"Attack rows: {int((combined['label'] == 1).sum()):,}")


if __name__ == "__main__":
    main()