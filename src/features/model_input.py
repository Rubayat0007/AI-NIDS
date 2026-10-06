"""Adapter from canonical flow features to the frozen model input format."""

from collections.abc import Mapping

import numpy as np

from .schema import FEATURE_NAMES


def features_to_model_input(features: Mapping[str, object]) -> np.ndarray:
    """Convert one canonical feature record into a model-ready matrix."""
    if not isinstance(features, Mapping):
        raise TypeError("features must be a mapping")

    actual_names = set(features)
    expected_names = set(FEATURE_NAMES)

    missing = expected_names - actual_names
    unexpected = actual_names - expected_names

    if missing:
        raise ValueError(
            f"missing model features: {sorted(missing)}"
        )

    if unexpected:
        raise ValueError(
            f"unexpected model features: {sorted(unexpected)}"
        )

    values = []

    for feature_name in FEATURE_NAMES:
        value = features[feature_name]

        if isinstance(value, bool):
            raise TypeError(
                f"model feature '{feature_name}' must be numeric, not bool"
            )

        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"model feature '{feature_name}' must be numeric"
            ) from exc

        if not np.isfinite(numeric_value):
            raise ValueError(
                f"model feature '{feature_name}' must be finite"
            )

        values.append(numeric_value)

    return np.asarray(values, dtype=np.float64).reshape(1, len(FEATURE_NAMES))
