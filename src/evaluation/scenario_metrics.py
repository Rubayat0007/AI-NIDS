"""Binary metrics for scenario-level detection results (torch-free)."""

from __future__ import annotations


def confusion(rows) -> dict:
    """Rows are (label, prediction) pairs with 0 = benign, 1 = attack."""
    tp = fp = tn = fn = 0

    for label, prediction in rows:
        if label == 1 and prediction == 1:
            tp += 1
        elif label == 0 and prediction == 0:
            tn += 1
        elif label == 0:
            fp += 1
        else:
            fn += 1

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(rows) -> dict:
    counts = confusion(rows)
    total = sum(counts.values())

    def ratio(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else 0.0

    precision = ratio(counts["tp"], counts["tp"] + counts["fp"])
    recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
    f1 = ratio(2 * precision * recall, precision + recall)

    return {
        **counts,
        "samples": total,
        "accuracy": ratio(counts["tp"] + counts["tn"], total),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": ratio(counts["fp"], counts["fp"] + counts["tn"]),
    }
