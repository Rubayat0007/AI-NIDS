"""Supplementary held-out error-slice analysis for the frozen CICIDS2017 model."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "cicids2017_binary.csv"
MODEL_PATH = (
    PROJECT_ROOT
    / "src"
    / "models"
    / "nids_random_forest_cicids2017.pkl"
)

RANDOM_STATE = 42
TEST_SIZE = 0.20
TARGET_COLUMN = "label"

FEATURES = [
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

SLICE_FEATURES = [
    "flow_duration",
    "flow_packets",
    "flow_bytes",
    "packet_rate",
    "active_time",
    "idle_time",
]


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    dataset = pd.read_csv(DATASET_PATH)

    required = FEATURES + [TARGET_COLUMN]
    missing = [column for column in required if column not in dataset.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    dataset = dataset[required].copy()
    dataset = dataset.replace([float("inf"), float("-inf")], pd.NA)
    dataset = dataset.dropna()

    return dataset


def normalize_labels(labels: pd.Series) -> pd.Series:
    return (
        labels.astype(str)
        .str.strip()
        .str.lower()
        .map(lambda value: 0 if value in {"benign", "normal", "0"} else 1)
    )


def make_quantile_slices(values: pd.Series) -> pd.Series:
    ranked = values.rank(method="first")
    return pd.qcut(
        ranked,
        q=4,
        labels=["Q1", "Q2", "Q3", "Q4"],
    )


def analyze_slice(
    labels: pd.Series,
    predictions: pd.Series,
    mask: pd.Series,
) -> tuple[int, int, int, int, float, float]:
    actual = labels[mask]
    predicted = predictions[mask]

    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    true_benign_predicted_benign = int(matrix[0, 0])
    false_positive = int(matrix[0, 1])
    false_negative = int(matrix[1, 0])
    true_attack_predicted_attack = int(matrix[1, 1])

    benign_total = true_benign_predicted_benign + false_positive
    attack_total = false_negative + true_attack_predicted_attack

    false_positive_rate = (
        false_positive / benign_total if benign_total else float("nan")
    )
    attack_recall = (
        true_attack_predicted_attack / attack_total
        if attack_total
        else float("nan")
    )

    return (
        len(actual),
        int(actual.sum()),
        false_positive,
        false_negative,
        false_positive_rate,
        attack_recall,
    )


def main() -> None:
    dataset = load_dataset()

    X = dataset[FEATURES]
    y = normalize_labels(dataset[TARGET_COLUMN])

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = joblib.load(MODEL_PATH)
    predictions = pd.Series(
        model.predict(X_test),
        index=X_test.index,
        name="prediction",
    )

    test_frame = X_test.copy()
    test_frame["label"] = y_test
    test_frame["prediction"] = predictions

    print("\n=== Supplementary Held-Out Error-Slice Analysis ===")
    print(f"Dataset rows:       {len(dataset):,}")
    print(f"Testing rows:       {len(test_frame):,}")
    print(f"Random state:       {RANDOM_STATE}")
    print(f"Test size:          {TEST_SIZE:.0%}")
    print("\nThis analysis is supplementary and does not replace the primary")
    print("held-out benchmark or alter the frozen model/dataset.")

    for feature in SLICE_FEATURES:
        test_frame["_slice"] = make_quantile_slices(test_frame[feature])

        print(f"\n=== {feature} quartiles ===")
        print(
            f"{'Slice':<6} {'Rows':>9} {'Attacks':>9} "
            f"{'FP':>8} {'FN':>8} {'Benign FPR':>12} {'Attack Recall':>14}"
        )
        print("-" * 78)

        for slice_name in ["Q1", "Q2", "Q3", "Q4"]:
            mask = test_frame["_slice"] == slice_name
            (
                rows,
                attacks,
                false_positive,
                false_negative,
                false_positive_rate,
                attack_recall,
            ) = analyze_slice(
                test_frame["label"],
                test_frame["prediction"],
                mask,
            )

            fpr_text = (
                f"{false_positive_rate:.4%}"
                if pd.notna(false_positive_rate)
                else "N/A"
            )
            recall_text = (
                f"{attack_recall:.4%}"
                if pd.notna(attack_recall)
                else "N/A"
            )

            print(
                f"{slice_name:<6} {rows:>9,} {attacks:>9,} "
                f"{false_positive:>8,} {false_negative:>8,} "
                f"{fpr_text:>12} {recall_text:>14}"
            )

    print("\n=== Analysis Complete ===")
    print("The frozen model was not modified or retrained.")
    print("The primary held-out evaluation methodology was not changed.")
    print("Quartile boundaries are descriptive test-set slices only.")


if __name__ == "__main__":
    main()
