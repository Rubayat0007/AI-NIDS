from pathlib import Path

import joblib

from src.features.schema import FEATURE_NAMES


MODEL_PATH = Path("src/models/nids_random_forest_cicids2017.pkl")


def test_saved_model_feature_schema_matches_canonical_schema():
    model = joblib.load(MODEL_PATH)

    assert hasattr(model, "feature_names_in_")
    assert list(model.feature_names_in_) == FEATURE_NAMES
