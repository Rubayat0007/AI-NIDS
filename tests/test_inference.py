import warnings

import numpy as np
import pytest

from src.features.model_input import features_to_model_input
from src.features.schema import FEATURE_NAMES
from src.inference import load_model, predict_features


def make_features():
    return {
        feature_name: float(index + 1)
        for index, feature_name in enumerate(FEATURE_NAMES)
    }


def test_frozen_model_predicts_canonical_feature_record():
    model = load_model()

    assert list(model.feature_names_in_) == FEATURE_NAMES
    assert model.n_features_in_ == len(FEATURE_NAMES)

    features = make_features()
    model_input = features_to_model_input(features)

    assert model_input.shape == (1, len(FEATURE_NAMES))

    with warnings.catch_warnings():
        warnings.simplefilter("error")

        result = predict_features(model, features)

    assert result["prediction"] in {0, 1}

    probabilities = result["probabilities"]

    assert isinstance(probabilities, np.ndarray)
    assert probabilities.shape == (2,)
    assert np.isfinite(probabilities).all()
    assert float(probabilities.sum()) == pytest.approx(1.0)
