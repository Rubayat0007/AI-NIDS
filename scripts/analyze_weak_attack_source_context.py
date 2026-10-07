from pathlib import Path
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_PATH = PROJECT_ROOT / "data" / "processed" / "cicids2017_binary.csv"

RANDOM_STATE = 42
TEST_SIZE = 0.20

WEAK_LABEL_PATTERNS = [
    "Web Attack",
    "Bot",
    "PortScan",
]


def main():
    if not PROCESSED_PATH.exists():
        raise FileNotFoundError(f"Processed dataset not found: {PROCESSED_PATH}")

    sys.path.insert(0, str(PROJECT_ROOT))

    from src.features.model_input import FEATURE_NAMES
    from src.inference import load_model
    from scripts.analyze_heldout_error_provenance import build_source_provenance

    df = pd.read_csv(PROCESSED_PATH)

    expected_columns = list(FEATURE_NAMES) + ["label"]
    if list(df.columns) != expected_columns:
        raise RuntimeError(
            "Frozen dataset columns do not match FEATURE_NAMES + label."
        )

    X = df[FEATURE_NAMES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int8)

    _, test_idx = train_test_split(
        np.arange(len(df)),
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    test_features = pd.DataFrame(
        X[test_idx],
        columns=FEATURE_NAMES,
    )

    model = load_model()

    predictions = model.predict(test_features)
    probabilities = model.predict_proba(test_features)[:, 1]

    provenance = build_source_provenance()

    if len(provenance) != len(df):
        raise RuntimeError(
            f"Provenance row count mismatch: {len(provenance)} != {len(df)}"
        )

    provenance_features = provenance[FEATURE_NAMES].to_numpy(dtype=np.float32)
    if not np.array_equal(provenance_features, X):
        raise RuntimeError(
            "Provenance feature rows do not exactly match frozen dataset."
        )

    provenance_labels = provenance["binary_label"].to_numpy(dtype=np.int8)
    if not np.array_equal(provenance_labels, y):
        raise RuntimeError(
            "Provenance labels do not exactly match frozen dataset."
        )

    test = pd.DataFrame(
        {
            "source_label": provenance.iloc[test_idx]["source_label"].to_numpy(),
            "source_file": provenance.iloc[test_idx]["source_file"].to_numpy(),
            "binary_label": y[test_idx],
            "prediction": predictions,
            "attack_probability": probabilities,
        }
    )

    weak_labels = []

    for pattern in WEAK_LABEL_PATTERNS:
        matches = sorted(
            label
            for label in test["source_label"].dropna().unique()
            if pattern in label
        )

        if pattern == "Web Attack":
            matches = [
                label
                for label in matches
                if "Sql Injection" not in label
            ]

        weak_labels.extend(matches)

    weak_labels = list(dict.fromkeys(weak_labels))

    print("=== Weak Attack Source-Context Diagnostic ===")
    print(f"Frozen rows:   {len(df):,}")
    print(f"Held-out rows: {len(test):,}")
    print()

    for label in weak_labels:
        subset = test[test["source_label"] == label].copy()

        if subset.empty:
            continue

        subset["is_fn"] = (
            (subset["binary_label"] == 1)
            & (subset["prediction"] == 0)
        )

        subset["is_correct_attack"] = (
            (subset["binary_label"] == 1)
            & (subset["prediction"] == 1)
        )

        attack_count = len(subset)
        fn_count = int(subset["is_fn"].sum())
        correct_count = int(subset["is_correct_attack"].sum())

        print(f"=== {label} ===")
        print(f"Attack rows:        {attack_count:,}")
        print(f"False negatives:    {fn_count:,}")
        print(f"Correct detections: {correct_count:,}")

        if attack_count:
            print(f"Overall recall:     {correct_count / attack_count:.4%}")

        print()

        rows = []

        for source_file, source_subset in subset.groupby(
            "source_file",
            sort=True,
        ):
            attack_rows = len(source_subset)
            fn_rows = int(source_subset["is_fn"].sum())
            correct_rows = int(source_subset["is_correct_attack"].sum())

            fn_prob = source_subset.loc[
                source_subset["is_fn"],
                "attack_probability",
            ].to_numpy(dtype=np.float64)

            correct_prob = source_subset.loc[
                source_subset["is_correct_attack"],
                "attack_probability",
            ].to_numpy(dtype=np.float64)

            rows.append(
                {
                    "source_file": source_file,
                    "attack_rows": attack_rows,
                    "fn": fn_rows,
                    "correct": correct_rows,
                    "recall": (
                        correct_rows / attack_rows
                        if attack_rows
                        else np.nan
                    ),
                    "fn_rate": (
                        fn_rows / attack_rows
                        if attack_rows
                        else np.nan
                    ),
                    "fn_prob_median": (
                        float(np.median(fn_prob))
                        if len(fn_prob)
                        else np.nan
                    ),
                    "correct_prob_median": (
                        float(np.median(correct_prob))
                        if len(correct_prob)
                        else np.nan
                    ),
                }
            )

        result = pd.DataFrame(rows)

        print(
            result.sort_values(
                ["fn", "attack_rows"],
                ascending=[False, False],
            ).to_string(
                index=False,
                float_format=lambda value: f"{value:.6g}",
            )
        )
        print()

        # Highlight only source contexts containing false negatives.
        fn_sources = result[result["fn"] > 0].copy()

        if not fn_sources.empty:
            print("FN concentration")
            total_fn = fn_sources["fn"].sum()

            for _, row in fn_sources.sort_values(
                "fn",
                ascending=False,
            ).iterrows():
                concentration = row["fn"] / total_fn
                print(
                    f"  {row['source_file']}: "
                    f"{int(row['fn']):,} FN "
                    f"({concentration:.2%} of this family's FN)"
                )

        print()

    print(
        "This is supplementary source-context analysis of the fixed "
        "held-out split. It does not modify the dataset, model, training "
        "procedure, or primary benchmark."
    )


if __name__ == "__main__":
    main()
