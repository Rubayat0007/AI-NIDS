import math

import pandas as pd

from scripts.analyze_heldout_error_slices import (
    analyze_slice,
    make_quantile_slices,
)


def test_make_quantile_slices_produces_four_equal_groups():
    values = pd.Series(range(100))
    slices = make_quantile_slices(values)

    assert slices.cat.categories.tolist() == ["Q1", "Q2", "Q3", "Q4"]
    assert slices.value_counts().sort_index().tolist() == [25, 25, 25, 25]


def test_analyze_slice_calculates_error_metrics():
    labels = pd.Series([0, 0, 0, 1, 1, 1])
    predictions = pd.Series([0, 1, 0, 1, 0, 1])
    mask = pd.Series([True, True, True, True, True, True])

    (
        rows,
        attacks,
        false_positive,
        false_negative,
        false_positive_rate,
        attack_recall,
    ) = analyze_slice(labels, predictions, mask)

    assert rows == 6
    assert attacks == 3
    assert false_positive == 1
    assert false_negative == 1
    assert false_positive_rate == 1 / 3
    assert attack_recall == 2 / 3


def test_analyze_slice_returns_nan_when_slice_has_no_benign_rows():
    labels = pd.Series([1, 1])
    predictions = pd.Series([1, 0])
    mask = pd.Series([True, True])

    result = analyze_slice(labels, predictions, mask)

    assert result[0] == 2
    assert result[1] == 2
    assert result[2] == 0
    assert result[3] == 1
    assert math.isnan(result[4])
    assert result[5] == 0.5


def test_analyze_slice_returns_nan_when_slice_has_no_attack_rows():
    labels = pd.Series([0, 0])
    predictions = pd.Series([0, 1])
    mask = pd.Series([True, True])

    result = analyze_slice(labels, predictions, mask)

    assert result[0] == 2
    assert result[1] == 0
    assert result[2] == 1
    assert result[3] == 0
    assert result[4] == 0.5
    assert math.isnan(result[5])
