import pytest

import src.predict as predict


def test_live_inference_is_explicitly_disabled_until_feature_pipeline_is_verified():
    assert predict.LIVE_INFERENCE_ENABLED is False


def test_live_prediction_refuses_unverified_feature_pipeline():
    predict.model = object()

    with pytest.raises(RuntimeError, match="Live inference"):
        predict.predict_traffic(
            packets=[object()],
            duration=1.0,
        )

