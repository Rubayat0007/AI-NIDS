"""Tests for scenario-level detection metrics."""

from src.evaluation.scenario_metrics import confusion, metrics


def test_confusion_counts():
    rows = [(1, 1), (1, 0), (0, 0), (0, 1)]

    assert confusion(rows) == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}


def test_metrics_on_a_perfect_run():
    result = metrics([(1, 1), (1, 1), (0, 0), (0, 0)])

    assert result["accuracy"] == 1.0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["false_positive_rate"] == 0.0


def test_metrics_when_nothing_is_detected():
    result = metrics([(1, 0), (1, 0), (0, 0)])

    assert result["tp"] == 0
    assert result["fn"] == 2
    assert result["recall"] == 0.0
    assert result["precision"] == 0.0
    assert result["f1"] == 0.0


def test_metrics_when_everything_is_flagged():
    result = metrics([(1, 1), (0, 1)])

    assert result["false_positive_rate"] == 1.0
    assert result["recall"] == 1.0
    assert result["precision"] == 0.5


def test_empty_input_is_zeroed_not_divided_by_zero():
    result = metrics([])

    assert result["samples"] == 0
    assert result["accuracy"] == 0.0
    assert result["f1"] == 0.0


def test_single_class_absence_does_not_crash():
    result = metrics([(0, 0), (0, 0)])

    assert result["recall"] == 0.0
    assert result["accuracy"] == 1.0
