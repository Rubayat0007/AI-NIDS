from pathlib import Path


DASHBOARD_SOURCE = (
    Path(__file__).resolve().parents[1] / "src" / "dashboard.py"
)


def test_dashboard_uses_isolated_capture_boundary():
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")

    assert "from src.capture import capture_network_traffic" in source
    assert "from predict import" not in source
    assert "predict_traffic(" not in source
    assert "load_model()" not in source


def test_dashboard_keeps_live_inference_explicitly_disabled():
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")

    assert "raise RuntimeError(" in source
    assert "Live inference is disabled:" in source
    assert "frozen CICIDS2017 training features." in source


def test_dashboard_binds_error_message_before_scheduling_callback():
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")

    assert "error_message = str(error)" in source
    assert "lambda message=error_message: detection_error(message)" in source
