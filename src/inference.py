"""Offline inference boundary for the frozen CICIDS2017 model."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .features.model_input import features_to_model_input
from .features.schema import FEATURE_NAMES


MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "nids_random_forest_cicids2017.pkl"
)


def load_model():
    """Load the frozen Random Forest model from the local artifact."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def predict_features(model, features):
    """Predict one canonical feature record with a supplied model."""
    model_input = features_to_model_input(features)

    model_frame = pd.DataFrame(
        model_input,
        columns=FEATURE_NAMES,
    )

    prediction = model.predict(model_frame)
    probabilities = model.predict_proba(model_frame)

    if prediction.shape != (1,):
        raise RuntimeError(
            f"unexpected prediction shape: {prediction.shape}"
        )

    if probabilities.shape != (1, 2):
        raise RuntimeError(
            f"unexpected probability shape: {probabilities.shape}"
        )

    if not np.isfinite(probabilities).all():
        raise RuntimeError(
            "model returned non-finite probabilities"
        )

    return {
        "prediction": int(prediction[0]),
        "probabilities": probabilities[0].astype(float),
    }
