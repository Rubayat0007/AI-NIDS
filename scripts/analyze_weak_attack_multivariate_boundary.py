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



def summarize_probabilities(probabilities):
    return {
        "min": float(np.min(probabilities)),
        "q25": float(np.quantile(probabilities, 0.25)),
        "median": float(np.median(probabilities)),
        "q75": float(np.quantile(probabilities, 0.75)),
        "max": float(np.max(probabilities)),
        "mean": float(np.mean(probabilities)),
    }


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
            "binary_label": y[test_idx],
            "prediction": predictions,
            "attack_probability": probabilities,
        }
    )

    test["error_type"] = np.select(
        [
            (test["binary_label"] == 0) & (test["prediction"] == 0),
            (test["binary_label"] == 0) & (test["prediction"] == 1),
            (test["binary_label"] == 1) & (test["prediction"] == 0),
            (test["binary_label"] == 1) & (test["prediction"] == 1),
        ],
        [
            "CORRECT",
            "FALSE_POSITIVE",
            "FALSE_NEGATIVE",
            "CORRECT",
        ],
        default="UNKNOWN",
    )

    # Leaf index of every held-out sample in every frozen RF tree.
    leaf_indices = model.apply(test_features)

    if leaf_indices.ndim != 2:
        raise RuntimeError(
            f"Unexpected Random Forest leaf representation shape: "
            f"{leaf_indices.shape}"
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

    print("=== Multivariate Random-Forest Error-Boundary Diagnostic ===")
    print(f"Frozen rows:          {len(df):,}")
    print(f"Held-out rows:        {len(test):,}")
    print(f"RF trees:             {leaf_indices.shape[1]:,}")
    print()

    for label in weak_labels:
        subset_positions = np.flatnonzero(
            test["source_label"].to_numpy() == label
        )

        fn_positions = subset_positions[
            test.iloc[subset_positions]["error_type"].to_numpy()
            == "FALSE_NEGATIVE"
        ]

        correct_positions = subset_positions[
            test.iloc[subset_positions]["error_type"].to_numpy()
            == "CORRECT"
        ]

        print(f"=== {label} ===")
        print(f"Attack rows:        {len(subset_positions):,}")
        print(f"False negatives:    {len(fn_positions):,}")
        print(f"Correct detections: {len(correct_positions):,}")
        print()

        if len(fn_positions) == 0 or len(correct_positions) == 0:
            print("Insufficient error-group overlap for analysis.")
            print()
            continue

        fn_prob = probabilities[fn_positions]
        correct_prob = probabilities[correct_positions]

        print("Attack probability")
        print(
            "  FALSE_NEGATIVE:",
            summarize_probabilities(fn_prob),
        )
        print(
            "  CORRECT:",
            summarize_probabilities(correct_prob),
        )
        print()

        # For every FN, find its closest correctly detected attack sample
        # in the frozen RF leaf space.
        #
        # Proximity = fraction of RF trees in which both samples reach
        # exactly the same leaf.
        best_proximities = []
        best_probability_gaps = []

        correct_leaves = leaf_indices[correct_positions]

        for fn_position in fn_positions:
            fn_leaf = leaf_indices[fn_position]

            proximities = np.mean(
                correct_leaves == fn_leaf,
                axis=1,
            )

            best_index = int(np.argmax(proximities))
            best_proximity = float(proximities[best_index])

            best_correct_position = correct_positions[best_index]

            best_proximities.append(best_proximity)
            best_probability_gaps.append(
                abs(
                    float(probabilities[fn_position])
                    - float(probabilities[best_correct_position])
                )
            )

        best_proximities = np.asarray(best_proximities)
        best_probability_gaps = np.asarray(best_probability_gaps)

        print("Nearest correctly detected attack in RF leaf space")
        print(
            f"  proximity min/median/q75/max: "
            f"{np.min(best_proximities):.6f} / "
            f"{np.median(best_proximities):.6f} / "
            f"{np.quantile(best_proximities, 0.75):.6f} / "
            f"{np.max(best_proximities):.6f}"
        )
        print(
            f"  probability-gap min/median/q75/max: "
            f"{np.min(best_probability_gaps):.6f} / "
            f"{np.median(best_probability_gaps):.6f} / "
            f"{np.quantile(best_probability_gaps, 0.75):.6f} / "
            f"{np.max(best_probability_gaps):.6f}"
        )
        print()

        proximity_thresholds = [0.25, 0.50, 0.75, 0.90]

        print("False negatives with a nearby correctly detected attack")
        for threshold in proximity_thresholds:
            fraction = float(
                np.mean(best_proximities >= threshold)
            )
            count = int(np.sum(best_proximities >= threshold))

            print(
                f"  proximity >= {threshold:.2f}: "
                f"{count:,}/{len(fn_positions):,} "
                f"({fraction:.2%})"
            )

        print()

    print(
        "Interpretation note: RF leaf proximity describes similarity inside "
        "the frozen model's tree partitions. It is diagnostic only and does "
        "not imply causality or justify retraining."
    )


if __name__ == "__main__":
    main()

