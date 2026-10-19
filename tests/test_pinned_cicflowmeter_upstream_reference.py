"""Regression fixtures captured from a pinned CICFlowMeter reference build.

Reference producer: https://github.com/ahlashkari/CICFlowMeter
Revision: 98a5ebad0df579cc8b43eedd3421b3ae87699901
Build used Java 8 (1.8.0_482) and the repository Gradle wrapper on Windows.
The expected values below were mapped by CSV column name from the reference
outputs generated on 2026-10-19. The raw CSV output SHA-256 values were:

* short_tcp: 76FA1803FDA0599AED4C57607CD0ADAB25D1939BAB8E940F907D540364DE43F1
* idle_gap:  FF340A757AD5A169BC86268898B5A987C5DE57AADC10E20243B9E2A423D92ACD

The source revision is a reproducible comparator, not proof that this exact
revision produced the historical CICIDS2017 training rows. Absolute PCAP time
is irrelevant to these features; timestamps are converted to offsets from the
first packet before extraction to avoid floating-point precision loss from the
epoch timestamp. Relative inter-packet intervals are preserved exactly.
"""

import hashlib
from decimal import Decimal
from pathlib import Path

import pytest
from scapy.utils import rdpcap

from src.features.flow import extract_flows
from src.features.schema import FEATURE_NAMES


FIXTURE_DIR = Path(__file__).parent / "fixtures"

REFERENCE_CASES = {
    "short_tcp": {
        "pcap": "cicflowmeter_98a5ebad_short_tcp.pcap",
        "sha256": "DA4A251CDE69F0CFF7377930BAB035A466E9C976FF732360F75E0F496EDF3189",
        "expected": {
            "flow_duration": 6000.0,
            "total_fwd_packets": 2.0,
            "total_bwd_packets": 2.0,
            "fwd_packet_length": 6.0,
            "bwd_packet_length": 8.0,
            "flow_bytes": 28.0,
            "flow_packets": 4.0,
            "flow_rate": 4666.666666666667,
            "packet_rate": 666.6666666666666,
            "avg_packet_size": 8.0,
            "syn_count": 2.0,
            "ack_count": 3.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "active_time": 0.0,
            "idle_time": 0.0,
            "header_length": 80.0,
            "down_up_ratio": 1.0,
            "fwd_iat_mean": 3000.0,
            "bwd_iat_mean": 5000.0,
        },
    },
    "idle_gap": {
        "pcap": "cicflowmeter_98a5ebad_idle_gap.pcap",
        "sha256": "B5ECF9AFC642064B1986097BDB8B7316C50CE23580E2ED2918365FCA7D269F15",
        "expected": {
            "flow_duration": 6001000.0,
            "total_fwd_packets": 2.0,
            "total_bwd_packets": 2.0,
            "fwd_packet_length": 6.0,
            "bwd_packet_length": 8.0,
            "flow_bytes": 28.0,
            "flow_packets": 4.0,
            "flow_rate": 4.665889018496917,
            "packet_rate": 0.6665555740709881,
            "avg_packet_size": 8.0,
            "syn_count": 2.0,
            "ack_count": 3.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "active_time": 1000.0,
            "idle_time": 5999000.0,
            "header_length": 80.0,
            "down_up_ratio": 1.0,
            "fwd_iat_mean": 6000000.0,
            "bwd_iat_mean": 6000000.0,
        },
    },
}


@pytest.mark.parametrize("case_name", tuple(REFERENCE_CASES))
def test_flow_features_match_pinned_cicflowmeter_reference(case_name):
    """Match all model features from the pinned upstream run, by name."""
    case = REFERENCE_CASES[case_name]
    fixture_path = FIXTURE_DIR / case["pcap"]
    raw_fixture = fixture_path.read_bytes()
    assert hashlib.sha256(raw_fixture).hexdigest().upper() == case["sha256"]

    packets = rdpcap(str(fixture_path))
    assert len(packets) == 4

    # Normalize epoch timestamps before converting to float. This is a
    # representation-only adjustment; packet order and relative intervals
    # remain unchanged.
    origin = Decimal(str(packets[0].time))
    for packet in packets:
        packet.time = float(Decimal(str(packet.time)) - origin)

    flows = extract_flows(packets)
    assert len(flows) == 1
    actual = flows[0]
    expected = case["expected"]

    assert list(actual) == FEATURE_NAMES
    assert set(actual) == set(expected) == set(FEATURE_NAMES)
    for feature_name in FEATURE_NAMES:
        assert actual[feature_name] == pytest.approx(
            expected[feature_name], rel=1e-9, abs=1e-6
        ), f"{case_name}: mismatched feature {feature_name}"
