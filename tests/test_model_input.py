import numpy as np
import pytest

from src.features.model_input import features_to_model_input
from src.features.schema import FEATURE_NAMES


def make_features():
    return {
        feature_name: float(index + 1)
        for index, feature_name in enumerate(FEATURE_NAMES)
    }


def test_features_to_model_input_preserves_canonical_order():
    features = {
        feature_name: float(index + 1)
        for index, feature_name in reversed(
            list(enumerate(FEATURE_NAMES))
        )
    }

    model_input = features_to_model_input(features)

    assert isinstance(model_input, np.ndarray)
    assert model_input.shape == (1, len(FEATURE_NAMES))
    assert model_input.dtype == np.float64
    assert model_input.tolist() == [
        [float(index + 1) for index in range(len(FEATURE_NAMES))]
    ]


def test_features_to_model_input_rejects_missing_feature():
    features = make_features()
    features.pop(FEATURE_NAMES[-1])

    with pytest.raises(ValueError, match="missing model features"):
        features_to_model_input(features)


def test_features_to_model_input_rejects_unexpected_feature():
    features = make_features()
    features["unexpected_feature"] = 1.0

    with pytest.raises(ValueError, match="unexpected model features"):
        features_to_model_input(features)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_features_to_model_input_rejects_non_finite_values(value):
    features = make_features()
    features["flow_duration"] = value

    with pytest.raises(ValueError, match="must be finite"):
        features_to_model_input(features)


def test_features_to_model_input_rejects_non_numeric_value():
    features = make_features()
    features["flow_duration"] = "not-a-number"

    with pytest.raises(TypeError, match="must be numeric"):
        features_to_model_input(features)


def test_features_to_model_input_rejects_boolean_value():
    features = make_features()
    features["flow_duration"] = True

    with pytest.raises(TypeError, match="not bool"):
        features_to_model_input(features)
