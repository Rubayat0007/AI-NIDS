# ============================================================
# AI-NIDS - MODEL TRAINING
# ============================================================

import os
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "src",
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "nids_random_forest.pkl"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)


# ============================================================
# DEFAULT FEATURES
# ============================================================
# If an existing trained model is available, its exact feature
# names will be used automatically instead of this list.

DEFAULT_FEATURES = [

    "flow_duration",

    "ack_count",

    "rst_count",

    "fin_count",

    "active_time",

    "idle_time",

    "header_length",

    "down_up_ratio",

    "fwd_iat_mean",

    "bwd_iat_mean",

    "fwd_packet_length",

    "bwd_packet_length",

    "flow_bytes",

    "flow_packets",

    "flow_rate",

    "packet_rate",

    "avg_packet_size",

    "total_fwd_packets",

    "total_bwd_packets",

    "fwd_packet_length_mean"

]


# ============================================================
# GET FEATURE NAMES
# ============================================================

def get_feature_names():

    # --------------------------------------------------------
    # Preserve feature names from existing model
    # --------------------------------------------------------

    if os.path.exists(MODEL_PATH):

        try:

            old_model = joblib.load(
                MODEL_PATH
            )

            if hasattr(
                old_model,
                "feature_names_in_"
            ):

                features = list(
                    old_model.feature_names_in_
                )

                if len(features) > 0:

                    print(
                        f"Using {len(features)} features "
                        "from existing trained model."
                    )

                    return features

        except Exception as error:

            print(
                "Could not read existing model features."
            )

            print(
                f"Reason: {error}"
            )

    print(
        f"Using default feature set: "
        f"{len(DEFAULT_FEATURES)} features."
    )

    return DEFAULT_FEATURES


# ============================================================
# CREATE DEMO DATASET
# ============================================================

def create_demo_dataset(
    samples=2000,
    random_state=42
):

    print()
    print("=" * 65)
    print("CREATING SYNTHETIC NETWORK TRAFFIC DATASET")
    print("=" * 65)

    rng = np.random.default_rng(
        random_state
    )

    features = get_feature_names()

    print(
        f"Samples : {samples}"
    )

    print(
        f"Features: {len(features)}"
    )

    # --------------------------------------------------------
    # Base feature matrix
    # --------------------------------------------------------

    data = {}

    for feature in features:

        # Generate reasonable positive network values
        data[feature] = rng.lognormal(
            mean=1.0,
            sigma=1.0,
            size=samples
        )

    df = pd.DataFrame(
        data
    )

    # --------------------------------------------------------
    # Normalize / scale selected features
    # --------------------------------------------------------

    for feature in df.columns:

        df[feature] = pd.to_numeric(
            df[feature],
            errors="coerce"
        )

        df[feature] = df[feature].replace(
            [np.inf, -np.inf],
            0
        )

        df[feature] = df[feature].fillna(
            0
        )

    # --------------------------------------------------------
    # Create realistic relationships between features
    # --------------------------------------------------------

    if "flow_duration" in df.columns:

        df["flow_duration"] = rng.uniform(
            0.01,
            30.0,
            samples
        )

    if "flow_packets" in df.columns:

        df["flow_packets"] = rng.integers(
            1,
            1000,
            samples
        )

    if "flow_bytes" in df.columns:

        df["flow_bytes"] = rng.integers(
            100,
            1000000,
            samples
        )

    if "packet_rate" in df.columns:

        if "flow_packets" in df.columns:

            if "flow_duration" in df.columns:

                df["packet_rate"] = (
                    df["flow_packets"]
                    /
                    (df["flow_duration"] + 0.01)
                )

    if "flow_rate" in df.columns:

        if "flow_bytes" in df.columns:

            if "flow_duration" in df.columns:

                df["flow_rate"] = (
                    df["flow_bytes"]
                    /
                    (df["flow_duration"] + 0.01)
                )

    if "avg_packet_size" in df.columns:

        if "flow_bytes" in df.columns:

            if "flow_packets" in df.columns:

                df["avg_packet_size"] = (
                    df["flow_bytes"]
                    /
                    (df["flow_packets"] + 1)
                )

    if "down_up_ratio" in df.columns:

        df["down_up_ratio"] = rng.uniform(
            0.1,
            5.0,
            samples
        )

    if "header_length" in df.columns:

        df["header_length"] = rng.uniform(
            20,
            500,
            samples
        )

    if "syn_count" in df.columns:

        df["syn_count"] = rng.integers(
            0,
            100,
            samples
        )

    if "ack_count" in df.columns:

        df["ack_count"] = rng.integers(
            0,
            300,
            samples
        )

    if "rst_count" in df.columns:

        df["rst_count"] = rng.integers(
            0,
            50,
            samples
        )

    if "fin_count" in df.columns:

        df["fin_count"] = rng.integers(
            0,
            50,
            samples
        )

    if "total_fwd_packets" in df.columns:

        df["total_fwd_packets"] = rng.integers(
            1,
            700,
            samples
        )

    if "total_bwd_packets" in df.columns:

        df["total_bwd_packets"] = rng.integers(
            1,
            700,
            samples
        )

    # --------------------------------------------------------
    # Create attack score
    # --------------------------------------------------------

    attack_score = np.zeros(
        samples,
        dtype=float
    )

    if "syn_count" in df.columns:

        attack_score += (
            df["syn_count"] * 0.05
        )

    if "rst_count" in df.columns:

        attack_score += (
            df["rst_count"] * 0.15
        )

    if "fin_count" in df.columns:

        attack_score += (
            df["fin_count"] * 0.05
        )

    if "packet_rate" in df.columns:

        packet_rate = df[
            "packet_rate"
        ]

        threshold = packet_rate.quantile(
            0.75
        )

        attack_score += (
            packet_rate > threshold
        ).astype(int) * 2.0

    if "flow_rate" in df.columns:

        flow_rate = df[
            "flow_rate"
        ]

        threshold = flow_rate.quantile(
            0.75
        )

        attack_score += (
            flow_rate > threshold
        ).astype(int) * 2.0

    if "down_up_ratio" in df.columns:

        ratio = df[
            "down_up_ratio"
        ]

        attack_score += (
            (ratio > 3.0) |
            (ratio < 0.25)
        ).astype(int) * 1.5

    if "flow_duration" in df.columns:

        duration = df[
            "flow_duration"
        ]

        attack_score += (
            duration < 0.1
        ).astype(int) * 1.0

    # --------------------------------------------------------
    # Add controlled noise
    # --------------------------------------------------------

    attack_score += rng.normal(
        0,
        0.8,
        samples
    )

    # --------------------------------------------------------
    # Generate binary labels
    # --------------------------------------------------------

    threshold = np.median(
        attack_score
    )

    df["label"] = (
        attack_score > threshold
    ).astype(int)

    # --------------------------------------------------------
    # Shuffle dataset
    # --------------------------------------------------------

    df = df.sample(
        frac=1,
        random_state=random_state
    ).reset_index(
        drop=True
    )

    print()
    print(
        f"Dataset created: {df.shape}"
    )

    print()
    print("Class distribution:")

    print(
        df["label"].value_counts()
    )

    return df


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(
    dataset,
    test_size=0.20,
    random_state=42
):

    print()
    print("=" * 65)
    print("TRAINING RANDOM FOREST MODEL")
    print("=" * 65)

    # --------------------------------------------------------
    # Features / target
    # --------------------------------------------------------

    features = [
        column
        for column in dataset.columns
        if column != "label"
    ]

    X = dataset[
        features
    ].copy()

    y = dataset[
        "label"
    ].copy()

    # --------------------------------------------------------
    # Clean data
    # --------------------------------------------------------

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [np.inf, -np.inf],
        0
    )

    X = X.fillna(
        0
    )

    # --------------------------------------------------------
    # Train / test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(

        X,

        y,

        test_size=test_size,

        random_state=random_state,

        stratify=y

    )

    print()
    print(
        f"Total samples : {len(X)}"
    )

    print(
        f"Training data : {len(X_train)}"
    )

    print(
        f"Testing data  : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    model = RandomForestClassifier(

        n_estimators=200,

        max_depth=18,

        min_samples_split=4,

        min_samples_leaf=2,

        class_weight="balanced",

        random_state=random_state,

        n_jobs=-1

    )

    print()
    print(
        "Training model..."
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed."
    )

    # --------------------------------------------------------
    # Test predictions
    # --------------------------------------------------------

    print()
    print(
        "Evaluating model..."
    )

    predictions = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print()
    print("=" * 65)
    print("MODEL PERFORMANCE")
    print("=" * 65)

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1-Score  : {f1 * 100:.2f}%"
    )

    print("=" * 65)

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    report = classification_report(
        y_test,
        predictions,
        zero_division=0
    )

    print()
    print("CLASSIFICATION REPORT")
    print("=" * 65)
    print(report)

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions
    )

    print()
    print("CONFUSION MATRIX")
    print("=" * 65)

    print(
        cm
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    joblib.dump(
        model,
        MODEL_PATH
    )

    print()
    print("=" * 65)
    print("MODEL SAVED SUCCESSFULLY")
    print("=" * 65)

    print(
        f"Location: {MODEL_PATH}"
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    metrics_path = os.path.join(
        RESULTS_DIR,
        "model_metrics.csv"
    )

    metrics_df = pd.DataFrame({

        "Metric": [

            "Accuracy",

            "Precision",

            "Recall",

            "F1-Score"

        ],

        "Score": [

            accuracy,

            precision,

            recall,

            f1

        ],

        "Percentage": [

            accuracy * 100,

            precision * 100,

            recall * 100,

            f1 * 100

        ]

    })

    metrics_df.to_csv(
        metrics_path,
        index=False
    )

    # --------------------------------------------------------
    # Save classification report
    # --------------------------------------------------------

    report_path = os.path.join(
        RESULTS_DIR,
        "classification_report.txt"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "AI-NIDS MODEL PERFORMANCE\n"
        )

        file.write(
            "=" * 65 + "\n\n"
        )

        file.write(
            "Model: Random Forest\n\n"
        )

        file.write(
            f"Accuracy  : {accuracy * 100:.2f}%\n"
        )

        file.write(
            f"Precision : {precision * 100:.2f}%\n"
        )

        file.write(
            f"Recall    : {recall * 100:.2f}%\n"
        )

        file.write(
            f"F1-Score  : {f1 * 100:.2f}%\n\n"
        )

        file.write(
            "Classification Report\n"
        )

        file.write(
            "=" * 65 + "\n"
        )

        file.write(
            report
        )

        file.write(
            "\n\nConfusion Matrix\n"
        )

        file.write(
            str(cm)
        )

    print()
    print(
        f"Metrics saved: {metrics_path}"
    )

    print(
        f"Report saved : {report_path}"
    )

    return model


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 65)
    print("AI-NIDS")
    print("AI-Based Network Intrusion Detection System")
    print("=" * 65)

    # --------------------------------------------------------
    # Create dataset
    # --------------------------------------------------------

    dataset = create_demo_dataset(
        samples=2000,
        random_state=42
    )

    # --------------------------------------------------------
    # Train model
    # --------------------------------------------------------

    model = train_model(
        dataset,
        test_size=0.20,
        random_state=42
    )

    print()
    print("=" * 65)
    print("TRAINING PIPELINE COMPLETE")
    print("=" * 65)

    print(
        f"Model: {MODEL_PATH}"
    )

    print(
        f"Results: {RESULTS_DIR}"
    )

    print("=" * 65)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()