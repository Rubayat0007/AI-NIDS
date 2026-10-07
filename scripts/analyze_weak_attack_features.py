"""Analyze feature distributions for weakly recalled held-out attack families."""

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

RANDOM_STATE = 42
TEST_SIZE = 0.20

WEAK_LABEL_PATTERNS = [
    "Web Attack",
    "Bot",
    "PortScan",
]


SUMMARY_QUANTILES = [
    0.05,
    0.25,
    0.50,
    0.75,
    0.95,
]


def main():
    if not PROCESSED_PATH.is_file():
        raise FileNotFoundError(
            f"Processed dataset not found: {PROCESSED_PATH}"
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

    test_X = X.iloc[test_indices].copy()
    test_y = y.iloc[test_indices].copy()

    model = load_model()
    predictions = model.predict(test_X).astype(int)

    test = test_X.copy()
    test["binary_label"] = test_y.to_numpy()
    test["prediction"] = predictions

    # Recover the original CICIDS2017 labels from the already-validated
    # provenance diagnostic rather than attempting a second reconstruction.
    from scripts.analyze_heldout_error_provenance import (
        build_source_provenance,
    )

    provenance = build_source_provenance()

    if len(provenance) != len(frozen):
        raise RuntimeError(
            "Source provenance row count does not match the frozen dataset."
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
        raise RuntimeError(
            "Source provenance features do not match the frozen dataset."
        )

    frozen_labels = frozen["label"].to_numpy(dtype="int8")
    provenance_labels = provenance["binary_label"].to_numpy(dtype="int8")

    if not np.array_equal(
        frozen_labels,
        provenance_labels,
    ):
        raise RuntimeError(
            "Source provenance labels do not match the frozen dataset."
        )

    test["source_label"] = provenance.iloc[test_indices][
        "source_label"
    ].to_numpy()

    available_labels = test["source_label"].dropna().unique().tolist()

    weak_labels = []
    for pattern in WEAK_LABEL_PATTERNS:
        matches = [
            label
            for label in available_labels
            if pattern in str(label)
        ]
        if pattern == "Web Attack":
            weak_labels.extend(
                label
                for label in matches
                if "Sql Injection" not in str(label)
            )
        else:
            weak_labels.extend(matches)

    weak_labels = list(dict.fromkeys(weak_labels))

    test["error_type"] = np.where(
        (test["binary_label"] == 0) & (test["prediction"] == 1),
        "FALSE_POSITIVE",
        np.where(
            (test["binary_label"] == 1) & (test["prediction"] == 0),
            "FALSE_NEGATIVE",
            "CORRECT",
        ),
    )

    print()
    print("=== Weak Attack Feature Distribution Diagnostic ===")
    print(f"Frozen rows:   {len(frozen):,}")
    print(f"Held-out rows: {len(test):,}")
    print()

    print("=== Weak Attack Class Counts ===")

    weak_counts = (
        test[test["source_label"].isin(weak_labels)]
        .groupby(["source_label", "error_type"])
        .size()
        .reset_index(name="rows")
        .sort_values(
            ["source_label", "error_type"],
        )
    )

    print(weak_counts.to_string(index=False))
    print()

    for label in weak_labels:
        attack = test[test["source_label"] == label]
        false_negative = attack[
            attack["error_type"] == "FALSE_NEGATIVE"
        ]
        correctly_detected = attack[
            attack["error_type"] == "CORRECT"
        ]

        print()
        print(f"=== {label} ===")
        print(
            f"Attack rows:          {len(attack):,}"
        )
        print(
            f"False negatives:      {len(false_negative):,}"
        )
        print(
            f"Correct detections:   {len(correctly_detected):,}"
        )

        if false_negative.empty or correctly_detected.empty:
            print(
                "Insufficient error/correct samples for within-class "
                "comparison."
            )
            continue

        print()
        print(
            "Feature medians: false negatives vs correctly detected"
        )

        rows = []

        for feature in FEATURE_NAMES:
            fn_values = false_negative[feature].to_numpy(
                dtype=float
            )
            correct_values = correctly_detected[feature].to_numpy(
                dtype=float
            )

            fn_median = float(np.median(fn_values))
            correct_median = float(np.median(correct_values))

            if correct_median != 0:
                median_ratio = fn_median / correct_median
            else:
                median_ratio = np.nan

            rows.append(
                {
                    "feature": feature,
                    "fn_median": fn_median,
                    "correct_median": correct_median,
                    "fn_to_correct_median_ratio": median_ratio,
                }
            )

        median_table = pd.DataFrame(rows)
        median_table["abs_log2_ratio"] = np.nan

        positive = (
            (median_table["fn_median"] > 0)
            & (median_table["correct_median"] > 0)
        )

        median_table.loc[positive, "abs_log2_ratio"] = np.abs(
            np.log2(
                median_table.loc[positive, "fn_median"]
                / median_table.loc[positive, "correct_median"]
            )
        )

        median_table = median_table.sort_values(
            "abs_log2_ratio",
            ascending=False,
            na_position="last",
        )

        print(
            median_table[
                [
                    "feature",
                    "fn_median",
                    "correct_median",
                    "fn_to_correct_median_ratio",
                ]
            ].head(10).to_string(
                index=False,
                formatters={
                    "fn_median": lambda value: f"{value:.6g}",
                    "correct_median": lambda value: f"{value:.6g}",
                    "fn_to_correct_median_ratio": (
                        lambda value: (
                            f"{value:.4f}"
                            if np.isfinite(value)
                            else "nan"
                        )
                    ),
                },
            )
        )

        print()
        print(
            "Feature quantiles: false negatives"
        )

        fn_quantiles = false_negative[FEATURE_NAMES].quantile(
            SUMMARY_QUANTILES
        ).T

        print(
            fn_quantiles.to_string(
                float_format=lambda value: f"{value:.6g}"
            )
        )

    print()
    print(
        "This is supplementary feature-distribution analysis of the "
        "fixed held-out split. It does not modify the dataset, model, "
        "training procedure, or primary benchmark."
    )


if __name__ == "__main__":
    main()

