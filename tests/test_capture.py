import pytest

import src.capture as capture


def test_capture_network_traffic_collects_packets(monkeypatch):
    packets = [object(), object()]

    def fake_sniff(prn, store, timeout):
        assert store is False
        assert timeout == pytest.approx(2.0)
        for packet in packets:
            prn(packet)

    monkeypatch.setattr(capture, "sniff", fake_sniff)
    monkeypatch.setattr(capture.time, "time", iter([10.0, 12.0]).__next__)

    result_packets, duration = capture.capture_network_traffic(2.0)

    assert result_packets == packets
    assert duration == pytest.approx(2.0)


def test_capture_network_traffic_returns_empty_result_on_capture_error(
    monkeypatch,
):
    def fake_sniff(**kwargs):
        raise RuntimeError("capture failed")

    monkeypatch.setattr(capture, "sniff", fake_sniff)

    assert capture.capture_network_traffic(2.0) == ([], 0.0)


@pytest.mark.parametrize("seconds", [-1.0, "invalid"])
def test_capture_network_traffic_rejects_invalid_duration(seconds):
    with pytest.raises((TypeError, ValueError)):
        capture.capture_network_traffic(seconds)