from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_binary.csv"
)

MODEL_DIR = PROJECT_ROOT / "src" / "models"
RESULTS_DIR = PROJECT_ROOT / "results"

MODEL_FILE = MODEL_DIR / "nids_random_forest_cicids2017.pkl"
CONFUSION_MATRIX_FILE = RESULTS_DIR / "cicids2017_confusion_matrix.png"
METRICS_FILE = RESULTS_DIR / "cicids2017_metrics.txt"


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


def main() -> None:
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

    print("Loading CIC-IDS2017 dataset...")
    df = pd.read_csv(DATA_FILE)

    print(f"Rows loaded: {len(df):,}")

    missing_columns = [
        column
        for column in FEATURES + ["label"]
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    X = df[FEATURES]
    y = df["label"]

    print(f"Benign samples: {(y == 0).sum():,}")
    print(f"Attack samples: {(y == 1).sum():,}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples: {len(X_test):,}")

    print("Training Random Forest model...")

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
        max_features="sqrt",
    )

    model.fit(X_train, y_train)

    print("Evaluating model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )
    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )
    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    matrix = confusion_matrix(y_test, predictions)

    print()
    print("CIC-IDS2017 evaluation results")
    print("--------------------------------")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print()
    print("Confusion matrix:")
    print(matrix)
    print()
    print(classification_report(
        y_test,
        predictions,
        target_names=["Benign", "Attack"],
        zero_division=0,
    ))

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(model, MODEL_FILE)

    display = ConfusionMatrixDisplay(
        confusion_matrix=matrix,
        display_labels=["Benign", "Attack"],
    )

    display.plot()
    plt.title("CIC-IDS2017 Random Forest Confusion Matrix")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_FILE, dpi=200)
    plt.close()

    with open(METRICS_FILE, "w", encoding="utf-8") as file:
        file.write("CIC-IDS2017 Random Forest Evaluation\n")
        file.write("====================================\n")
        file.write(f"Dataset rows: {len(df):,}\n")
        file.write(f"Training rows: {len(X_train):,}\n")
        file.write(f"Testing rows: {len(X_test):,}\n")
        file.write(f"Accuracy: {accuracy:.6f}\n")
        file.write(f"Precision: {precision:.6f}\n")
        file.write(f"Recall: {recall:.6f}\n")
        file.write(f"F1-score: {f1:.6f}\n")
        file.write("\nConfusion matrix:\n")
        file.write(str(matrix))
        file.write("\n\nClassification report:\n")
        file.write(classification_report(
            y_test,
            predictions,
            target_names=["Benign", "Attack"],
            zero_division=0,
        ))

    print()
    print(f"Model saved to: {MODEL_FILE}")
    print(f"Confusion matrix saved to: {CONFUSION_MATRIX_FILE}")
    print(f"Metrics saved to: {METRICS_FILE}")


if __name__ == "__main__":
    main()