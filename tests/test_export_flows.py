"""Tests for the pcap -> labelled-flow export harness."""

import csv
import subprocess
import sys
from pathlib import Path

import pytest

scapy_all = pytest.importorskip("scapy.all")

from src.features.schema import FEATURE_NAMES  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "scripts" / "export_flows.py"


def make_pcap(path: Path) -> None:
    IP = scapy_all.IP
    TCP = scapy_all.TCP

    forward = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=12345, dport=443, flags="PA") / b"req"
    backward = IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=12345, flags="PA") / b"res"
    forward.time = 1_000_000.000
    backward.time = 1_000_000.100

    scapy_all.wrpcap(str(path), [forward, backward])


def run(*arguments):
    return subprocess.run(
        [sys.executable, str(TOOL), *map(str, arguments)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_export_writes_canonical_columns(tmp_path):
    pcap = tmp_path / "capture.pcap"
    output = tmp_path / "flows.csv"
    make_pcap(pcap)

    result = run("--pcap", pcap, "--output", output)

    assert result.returncode == 0, result.stderr

    with output.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert list(rows[0].keys()) == ["flow_id", *FEATURE_NAMES, "label"]
    assert rows
    assert all(row["label"] == "" for row in rows)


def test_labels_are_not_inferred(tmp_path):
    pcap = tmp_path / "capture.pcap"
    output = tmp_path / "flows.csv"
    make_pcap(pcap)

    run("--pcap", pcap, "--output", output)

    text = output.read_text(encoding="utf-8").strip().splitlines()
    assert all(line.endswith(",") for line in text[1:])


def test_validate_accepts_a_labelled_file(tmp_path):
    path = tmp_path / "labelled.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["flow_id", "label"])
        writer.writerow(["flow-00000", "benign"])
        writer.writerow(["flow-00001", "attack"])

    result = run("--validate", path)

    assert result.returncode == 0, result.stderr
    assert "STATUS: PASS" in result.stdout


def test_validate_rejects_unlabelled_rows(tmp_path):
    path = tmp_path / "labelled.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["flow_id", "label"])
        writer.writerow(["flow-00000", ""])

    result = run("--validate", path)

    assert result.returncode == 1
    assert "unlabelled" in result.stderr


def test_validate_rejects_unknown_labels(tmp_path):
    path = tmp_path / "labelled.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["flow_id", "label"])
        writer.writerow(["flow-00000", "maybe"])

    result = run("--validate", path)

    assert result.returncode == 1
    assert "invalid labels" in result.stderr


def test_missing_pcap_is_reported(tmp_path):
    result = run("--pcap", tmp_path / "absent.pcap", "--output", tmp_path / "out.csv")

    assert result.returncode == 2
    assert "not found" in result.stderr.lower()
