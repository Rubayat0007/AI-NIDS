from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    f1_score,
    precision_score,
    recall_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_binary.csv"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "src"
    / "models"
    / "nids_random_forest_cicids2017.pkl"
)

RESULTS_DIR = PROJECT_ROOT / "results"

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

    if not MODEL_FILE.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_FILE}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading CICIDS2017 dataset...")
    df = pd.read_csv(DATA_FILE)

    missing_columns = [
        column
        for column in FEATURES + ["label"]
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    model = joblib.load(MODEL_FILE)

    X = df[FEATURES]
    y = df["label"]

    predictions = model.predict(X)

    accuracy = accuracy_score(y, predictions)
    precision = precision_score(
        y,
        predictions,
        zero_division=0,
    )
    recall = recall_score(
        y,
        predictions,
        zero_division=0,
    )
    f1 = f1_score(
        y,
        predictions,
        zero_division=0,
    )

    report = classification_report(
        y,
        predictions,
        target_names=["Benign", "Attack"],
        zero_division=0,
    )

    matrix = confusion_matrix(y, predictions)

    print("\nCICIDS2017 model evaluation")
    print("---------------------------")
    print(f"Dataset rows: {len(df):,}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("\nClassification report:")
    print(report)
    print("\nConfusion matrix:")
    print(matrix)

    metrics_file = RESULTS_DIR / "cicids2017_evaluation_metrics.txt"

    with metrics_file.open("w", encoding="utf-8") as file:
        file.write("AI-NIDS CICIDS2017 Evaluation\n")
        file.write("============================\n")
        file.write(f"Dataset rows: {len(df):,}\n")
        file.write(f"Accuracy: {accuracy:.6f}\n")
        file.write(f"Precision: {precision:.6f}\n")
        file.write(f"Recall: {recall:.6f}\n")
        file.write(f"F1-score: {f1:.6f}\n\n")
        file.write("Classification report:\n")
        file.write(report)
        file.write("\nConfusion matrix:\n")
        file.write(str(matrix))

    report_file = RESULTS_DIR / "cicids2017_classification_report.txt"
    report_file.write_text(report, encoding="utf-8")

    confusion_file = RESULTS_DIR / "cicids2017_confusion_matrix.png"

    display = ConfusionMatrixDisplay(
        confusion_matrix=matrix,
        display_labels=["Benign", "Attack"],
    )

    display.plot()
    plt.title("AI-NIDS CICIDS2017 Confusion Matrix")
    plt.tight_layout()
    plt.savefig(confusion_file, dpi=300)
    plt.close()

    print("\nGenerated files:")
    print(metrics_file)
    print(report_file)
    print(confusion_file)


if __name__ == "__main__":
    main()