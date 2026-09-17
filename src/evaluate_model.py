from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_binary.csv"
)
MODEL_PATH = (
    PROJECT_ROOT
    / "src"
    / "models"
    / "nids_random_forest_cicids2017.pkl"
)

TARGET_COLUMN = "label"

RANDOM_STATE = 42
TEST_SIZE = 0.20

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


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    dataset = pd.read_csv(DATASET_PATH)

    missing_columns = [
        column
        for column in FEATURES + [TARGET_COLUMN]
        if column not in dataset.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    dataset = dataset[FEATURES + [TARGET_COLUMN]].copy()

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


def main() -> None:
    dataset = load_dataset()

    X = dataset[FEATURES]
    y = normalize_labels(dataset[TARGET_COLUMN])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = joblib.load(MODEL_PATH)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    matrix = confusion_matrix(y_test, predictions)

    print("\n=== Reproducible Held-Out Evaluation ===")
    print(f"Dataset rows:       {len(dataset):,}")
    print(f"Training rows:      {len(X_train):,}")
    print(f"Testing rows:       {len(X_test):,}")
    print(f"Random state:       {RANDOM_STATE}")
    print(f"Test size:          {TEST_SIZE:.0%}")

    print("\n=== Metrics ===")
    print(f"Accuracy:           {accuracy:.4%}")
    print(f"Precision:          {precision:.4%}")
    print(f"Recall:             {recall:.4%}")
    print(f"F1-score:           {f1:.4%}")

    print("\n=== Classification Report ===")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Benign", "Attack"],
            zero_division=0,
        )
    )

    print("=== Confusion Matrix ===")
    print(matrix)

    print("\nMatrix layout:")
    print("[[true_benign_predicted_benign, true_benign_predicted_attack],")
    print(" [true_attack_predicted_benign, true_attack_predicted_attack]]")


if __name__ == "__main__":
    main()