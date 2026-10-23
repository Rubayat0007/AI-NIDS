from pathlib import Path

import joblib

from src.features.schema import FEATURE_NAMES


MODEL_PATH = Path("src/models/nids_random_forest_cicids2017.pkl")


def test_saved_model_feature_schema_matches_canonical_schema():
    model = joblib.load(MODEL_PATH)

    assert hasattr(model, "feature_names_in_")
    assert list(model.feature_names_in_) == FEATURE_NAMES


# Environment gate: the frozen artifact is not committed.
import pytest as _pytest
from pathlib import Path as _Path

_MODEL_PATH = _Path(__file__).resolve().parents[1] / "src" / "models" / "nids_random_forest_cicids2017.pkl"
pytestmark = _pytest.mark.skipif(
    not _MODEL_PATH.exists(),
    reason=f"frozen model artifact not present: {_MODEL_PATH}",
)
