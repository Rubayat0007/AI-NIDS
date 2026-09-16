# ============================================================
# AI-NIDS - MODEL EVALUATION
# ============================================================

import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from model_train import create_demo_dataset


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "src",
    "models",
    "nids_random_forest.pkl"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 65)
print("AI-NIDS MODEL EVALUATION")
print("=" * 65)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

print()
print("Loading trained Random Forest model...")

if not os.path.exists(MODEL_PATH):

    raise FileNotFoundError(
        f"\nModel not found:\n{MODEL_PATH}"
    )

model = joblib.load(
    MODEL_PATH
)

print("Model loaded successfully.")
print(
    f"Model type: {type(model).__name__}"
)


# ============================================================
# GET MODEL FEATURES
# ============================================================

if not hasattr(
    model,
    "feature_names_in_"
):

    raise RuntimeError(
        "\nThe trained model does not contain "
        "feature_names_in_."
    )

MODEL_FEATURES = list(
    model.feature_names_in_
)

print()
print(
    f"Number of model features: {len(MODEL_FEATURES)}"
)

print()
print("Model features:")

for number, feature in enumerate(
    MODEL_FEATURES,
    start=1
):

    print(
        f"{number:02d}. {feature}"
    )


# ============================================================
# CREATE EVALUATION DATASET
# ============================================================

print()
print("=" * 65)
print("CREATING EVALUATION DATASET")
print("=" * 65)

dataset = create_demo_dataset()

print()
print(
    f"Dataset shape: {dataset.shape}"
)

print(
    f"Dataset columns: {len(dataset.columns)}"
)


# ============================================================
# DISPLAY DATASET COLUMNS
# ============================================================

print()
print("Available dataset columns:")

for number, column in enumerate(
    dataset.columns,
    start=1
):

    print(
        f"{number:02d}. {column}"
    )


# ============================================================
# FIND TARGET COLUMN
# ============================================================

possible_target_columns = [

    "label",
    "Label",

    "target",
    "Target",

    "attack",
    "Attack",

    "class",
    "Class",

    "y",
    "Y"
]

target_column = None


for column in possible_target_columns:

    if column in dataset.columns:

        target_column = column

        break


# If no standard target name exists,
# use the last column.

if target_column is None:

    target_column = dataset.columns[-1]


print()
print(
    f"Target column: {target_column}"
)


# ============================================================
# CHECK REQUIRED FEATURES
# ============================================================

missing_features = [

    feature

    for feature in MODEL_FEATURES

    if feature not in dataset.columns

]


if missing_features:

    print()
    print("=" * 65)
    print("MISSING FEATURES")
    print("=" * 65)

    for feature in missing_features:

        print(
            f"- {feature}"
        )

    raise ValueError(
        "\nThe evaluation dataset does not contain "
        "all features required by the trained model."
    )


# ============================================================
# PREPARE FEATURES
# ============================================================

X = dataset[
    MODEL_FEATURES
].copy()


# ============================================================
# PREPARE TARGET
# ============================================================

y = dataset[
    target_column
].copy()


# ============================================================
# CLEAN FEATURES
# ============================================================

print()
print("Cleaning evaluation data...")

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

X = X.replace(
    [float("inf"), float("-inf")],
    0
)

X = X.fillna(0)


# ============================================================
# CHECK TARGET
# ============================================================

print()
print("Target distribution:")

print(
    y.value_counts()
)


# ============================================================
# MODEL PREDICTION
# ============================================================

print()
print("=" * 65)
print("RUNNING MODEL PREDICTIONS")
print("=" * 65)

y_pred = model.predict(
    X
)

print(
    f"Predictions generated: {len(y_pred)}"
)


# ============================================================
# CALCULATE METRICS
# ============================================================

accuracy = accuracy_score(
    y,
    y_pred
)

precision = precision_score(
    y,
    y_pred,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y,
    y_pred,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y,
    y_pred,
    average="weighted",
    zero_division=0
)


# ============================================================
# DISPLAY MODEL PERFORMANCE
# ============================================================

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


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print()
print("=" * 65)
print("CLASSIFICATION REPORT")
print("=" * 65)

report = classification_report(
    y,
    y_pred,
    zero_division=0
)

print(report)


# ============================================================
# SAVE CLASSIFICATION REPORT
# ============================================================

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
        "AI-NIDS MODEL EVALUATION\n"
    )

    file.write(
        "=" * 65 + "\n\n"
    )

    file.write(
        "Model: Random Forest\n"
    )

    file.write(
        f"Evaluation Samples: {len(X)}\n\n"
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
        "CLASSIFICATION REPORT\n"
    )

    file.write(
        "=" * 65 + "\n"
    )

    file.write(
        report
    )


# ============================================================
# CONFUSION MATRIX
# ============================================================

print()
print("Generating confusion matrix...")

cm = confusion_matrix(
    y,
    y_pred
)

fig, ax = plt.subplots(
    figsize=(7, 6)
)

display = ConfusionMatrixDisplay(
    confusion_matrix=cm
)

display.plot(
    ax=ax
)

ax.set_title(
    "AI-NIDS Random Forest Confusion Matrix"
)

plt.tight_layout()


confusion_path = os.path.join(
    RESULTS_DIR,
    "confusion_matrix.png"
)

plt.savefig(
    confusion_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# SAVE METRICS CSV
# ============================================================

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


# ============================================================
# SAVE PREDICTIONS
# ============================================================

predictions_path = os.path.join(
    RESULTS_DIR,
    "evaluation_predictions.csv"
)

prediction_df = pd.DataFrame({

    "actual": y.values,

    "predicted": y_pred

})


prediction_df.to_csv(
    predictions_path,
    index=False
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print()
print("=" * 65)
print("EVALUATION COMPLETE")
print("=" * 65)

print()
print("Generated files:")

print()
print(
    f"1. Classification Report:"
)

print(
    f"   {report_path}"
)

print()
print(
    f"2. Confusion Matrix:"
)

print(
    f"   {confusion_path}"
)

print()
print(
    f"3. Model Metrics:"
)

print(
    f"   {metrics_path}"
)

print()
print(
    f"4. Evaluation Predictions:"
)

print(
    f"   {predictions_path}"
)

print()
print("=" * 65)