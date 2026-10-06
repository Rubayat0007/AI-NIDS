"""Measure live-vs-frozen feature distribution shift with a larger sample."""

from __future__ import annotations

import math
from pathlib import Path
import sys

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.capture import capture_network_traffic
from src.features.flow import FEATURE_NAMES, extract_flows
from src.features.model_eligibility import filter_model_eligible_flows


CAPTURE_SECONDS = 60.0
MIN_LIMITED_SAMPLE_FLOWS = 30
MIN_ADEQUATE_SAMPLE_FLOWS = 100

SUMMARY_QUANTILES = (
    0.00,
    0.50,
    0.95,
    0.99,
    1.00,
)

NONNEGATIVE_FEATURES = {
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes",
    "flow_packets",
    "flow_rate",
    "packet_rate",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "active_time",
    "idle_time",
    "header_length",
    "down_up_ratio",
    "fwd_iat_mean",
    "bwd_iat_mean",
}


def find_frozen_dataset() -> Path:
    candidates = sorted(
        path
        for path in (PROJECT_ROOT / "data" / "processed").glob("*.csv")
        if path.is_file()
    )

    if len(candidates) != 1:
        raise RuntimeError(
            "Expected exactly one processed CSV in data/processed; "
            f"found {len(candidates)}: {candidates}"
        )

    return candidates[0]


def validate_live_features(
    features: dict[str, object],
    index: int,
) -> None:
    actual_names = list(features)

    if actual_names != FEATURE_NAMES:
        raise RuntimeError(
            f"flow {index}: feature schema mismatch: {actual_names}"
        )

    for name in FEATURE_NAMES:
        value = features[name]

        if isinstance(value, bool):
            raise RuntimeError(
                f"flow {index}: feature {name!r} is boolean"
            )

        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"flow {index}: feature {name!r} is not numeric"
            ) from exc

        if not math.isfinite(numeric_value):
            raise RuntimeError(
                f"flow {index}: feature {name!r} is not finite"
            )

        if name in NONNEGATIVE_FEATURES and numeric_value < 0.0:
            raise RuntimeError(
                f"flow {index}: feature {name!r} is negative"
            )


def build_live_frame(
    flows: list[dict[str, object]],
) -> pd.DataFrame:
    for index, features in enumerate(flows, start=1):
        validate_live_features(features, index)

    frame = pd.DataFrame(flows, columns=FEATURE_NAMES)

    for name in FEATURE_NAMES:
        frame[name] = pd.to_numeric(frame[name], errors="raise")

    values = frame.to_numpy(dtype=np.float64)

    if not np.isfinite(values).all():
        raise RuntimeError(
            "live feature frame contains non-finite values"
        )

    return frame


def summarize(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for name in FEATURE_NAMES:
        series = frame[name].astype(np.float64)

        row = {
            "feature": name,
            "count": int(series.size),
            "mean": float(series.mean()),
            "std": float(series.std(ddof=0)),
            "zero_fraction": float((series == 0.0).mean()),
        }

        for quantile in SUMMARY_QUANTILES:
            label = f"q{int(quantile * 100):02d}"
            row[label] = float(series.quantile(quantile))

        rows.append(row)

    return pd.DataFrame(rows)


def classify_sample_size(flow_count: int) -> str:
    if flow_count < MIN_LIMITED_SAMPLE_FLOWS:
        return "INSUFFICIENT"

    if flow_count < MIN_ADEQUATE_SAMPLE_FLOWS:
        return "LIMITED_SAMPLE"

    return "ADEQUATE_FOR_DESCRIPTIVE_COMPARISON"


def print_comparison(
    training_summary: pd.DataFrame,
    live_summary: pd.DataFrame,
) -> None:
    training_by_feature = training_summary.set_index("feature")
    live_by_feature = live_summary.set_index("feature")

    rows = []

    for name in FEATURE_NAMES:
        train = training_by_feature.loc[name]
        live = live_by_feature.loc[name]

        rows.append(
            {
                "feature": name,
                "train_median": float(train["q50"]),
                "live_median": float(live["q50"]),
                "train_p95": float(train["q95"]),
                "live_p95": float(live["q95"]),
                "train_zero_fraction": float(train["zero_fraction"]),
                "live_zero_fraction": float(live["zero_fraction"]),
            }
        )

    comparison = pd.DataFrame(rows)

    print()
    print("EXTENDED FEATURE DISTRIBUTION COMPARISON")
    print("=" * 125)
    print(
        f"{'Feature':<22}"
        f"{'Train median':>16}"
        f"{'Live median':>16}"
        f"{'Train p95':>16}"
        f"{'Live p95':>16}"
        f"{'Train zero%':>14}"
        f"{'Live zero%':>14}"
    )
    print("-" * 125)

    for _, row in comparison.iterrows():
        print(
            f"{row['feature']:<22}"
            f"{row['train_median']:>16.6g}"
            f"{row['live_median']:>16.6g}"
            f"{row['train_p95']:>16.6g}"
            f"{row['live_p95']:>16.6g}"
            f"{row['train_zero_fraction'] * 100:>13.2f}%"
            f"{row['live_zero_fraction'] * 100:>13.2f}%"
        )

    print("=" * 125)


def main() -> None:
    dataset_path = find_frozen_dataset()

    print(f"Frozen dataset: {dataset_path}")
    print(f"Loading frozen distribution from {dataset_path}...")

    training = pd.read_csv(
        dataset_path,
        usecols=FEATURE_NAMES,
    )

    if list(training.columns) != FEATURE_NAMES:
        raise RuntimeError(
            "frozen dataset feature order does not match FEATURE_NAMES"
        )

    if len(training) == 0:
        raise RuntimeError("frozen dataset contains no rows")

    print(f"Frozen rows: {len(training):,}")

    print()
    print(f"Capturing live traffic for {CAPTURE_SECONDS:g} seconds...")
    packets, elapsed = capture_network_traffic(CAPTURE_SECONDS)

    print(f"Captured packets: {len(packets)}")
    print(f"Elapsed seconds:  {elapsed:.3f}")

    if not math.isfinite(elapsed) or elapsed < 0.0:
        raise RuntimeError(
            f"invalid capture duration: {elapsed}"
        )

    if not packets:
        raise RuntimeError(
            "No packets captured; extended distribution validation "
            "cannot proceed."
        )

    flows = extract_flows(packets)

    print(f"Extracted flows: {len(flows)}")

    if not flows:
        raise RuntimeError(
            "Packets were captured but no flows were extracted."
        )

    eligible_flows = filter_model_eligible_flows(flows)
    excluded_flows = len(flows) - len(eligible_flows)

    print(f"Model-eligible flows: {len(eligible_flows)}")
    print(f"Singleton flows excluded: {excluded_flows}")

    sample_class = classify_sample_size(len(eligible_flows))

    if sample_class == "INSUFFICIENT":
        raise RuntimeError(
            "Insufficient model-eligible live flows for this diagnostic: "
            f"{len(eligible_flows)} < {MIN_LIMITED_SAMPLE_FLOWS}"
        )

    live = build_live_frame(eligible_flows)

    training_summary = summarize(training)
    live_summary = summarize(live)

    print()
    print("SAMPLE SIZES")
    print("=" * 60)
    print(f"Frozen rows:          {len(training):,}")
    print(f"Live eligible flows:  {len(live):,}")
    print(f"Sample classification: {sample_class}")
    print(f"Live captured packets:{len(packets):,}")
    print(f"Capture duration:     {elapsed:.3f} seconds")
    print("=" * 60)

    print_comparison(training_summary, live_summary)

    print()
    print("EXTENDED DISTRIBUTION VALIDATION COMPLETE")
    print("Comparison used model-eligible multi-packet flows only.")
    print("Sample classification is an evidence-strength guard, not a compatibility test.")
    print("ML inference was not performed.")
    print("The frozen dataset was read-only.")
    print("This diagnostic does not authorize live inference.")


if __name__ == "__main__":
    main()
