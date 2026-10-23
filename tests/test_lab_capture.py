"""Tests for the lab capture labelling helpers (no live capture needed)."""

import csv
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lab_capture.py"
_spec = importlib.util.spec_from_file_location("lab_capture", _SCRIPT)
lab_capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_capture)

LABEL_COLUMNS = lab_capture.LABEL_COLUMNS
append_labels = lab_capture.append_labels
label_row = lab_capture.label_row


def test_label_row_shape():
    row = label_row("scan", 1, 100.0, 160.5, "scan.pcap")

    assert row == {
        "scenario": "scan",
        "label": 1,
        "start_epoch": 100.0,
        "end_epoch": 160.5,
        "pcap": "scan.pcap",
    }


def test_label_must_be_binary():
    with pytest.raises(ValueError):
        label_row("scan", 2, 0.0, 1.0, "x.pcap")


def test_end_cannot_precede_start():
    with pytest.raises(ValueError):
        label_row("scan", 1, 10.0, 5.0, "x.pcap")


def test_header_written_once(tmp_path):
    path = tmp_path / "labels.csv"
    append_labels(path, label_row("benign", 0, 1.0, 2.0, "a.pcap"))
    append_labels(path, label_row("scan", 1, 3.0, 4.0, "b.pcap"))

    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert [row["scenario"] for row in rows] == ["benign", "scan"]
    assert tuple(rows[0]) == LABEL_COLUMNS
