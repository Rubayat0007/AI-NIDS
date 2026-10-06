"""Verify exact reproduction of the frozen CICIDS2017 processed dataset."""

from pathlib import Path
import sys

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.prepare_cicids2017 import MODEL_FEATURES, process_file


RAW_DIR = PROJECT_ROOT / "data" / "raw" / "MachineLearningCVE"
FROZEN_FILE = PROJECT_ROOT / "data" / "processed" / "cicids2017_binary.csv"


def main() -> None:
    raw_files = sorted(RAW_DIR.glob("*.csv"))

    if not raw_files:
        raise FileNotFoundError(f"No raw CSV files found in: {RAW_DIR}")

    if not FROZEN_FILE.is_file():
        raise FileNotFoundError(
            f"Frozen processed dataset not found: {FROZEN_FILE}"
        )

    frames = [
        process_file(csv_file)
        for csv_file in raw_files
    ]

    regenerated = pd.concat(
        frames,
        ignore_index=True,
    ).drop_duplicates()

    regenerated[MODEL_FEATURES] = regenerated[MODEL_FEATURES].astype(
        "float32"
    )
    regenerated["label"] = regenerated["label"].astype("int8")

    frozen = pd.read_csv(FROZEN_FILE)

    print(f"Regenerated shape: {regenerated.shape}")
    print(f"Frozen shape:      {frozen.shape}")

    if regenerated.shape != frozen.shape:
        raise SystemExit("FAIL: dataset shapes differ")

    if list(regenerated.columns) != list(frozen.columns):
        raise SystemExit("FAIL: column order differs")

    regenerated_features = regenerated[MODEL_FEATURES].to_numpy(
        dtype=np.float32
    )
    frozen_features = frozen[MODEL_FEATURES].to_numpy(
        dtype=np.float32
    )

    regenerated_labels = regenerated["label"].to_numpy(
        dtype=np.int8
    )
    frozen_labels = frozen["label"].to_numpy(
        dtype=np.int8
    )

    feature_equal = np.array_equal(
        regenerated_features,
        frozen_features,
        equal_nan=True,
    )
    label_equal = np.array_equal(
        regenerated_labels,
        frozen_labels,
    )

    print(f"Feature values exactly equal: {feature_equal}")
    print(f"Labels exactly equal:          {label_equal}")

    if not feature_equal:
        differing_cells = np.count_nonzero(
            regenerated_features != frozen_features
        )
        differing_rows = np.count_nonzero(
            np.any(
                regenerated_features != frozen_features,
                axis=1,
            )
        )
        print(f"Differing feature cells: {differing_cells:,}")
        print(f"Differing feature rows:  {differing_rows:,}")

    if not label_equal:
        differing_labels = np.count_nonzero(
            regenerated_labels != frozen_labels
        )
        print(f"Differing labels: {differing_labels:,}")

    if not feature_equal or not label_equal:
        raise SystemExit("FAIL: frozen dataset reproduction mismatch")

    print("EXACT REPRODUCTION: PASS")


if __name__ == "__main__":
    main()
