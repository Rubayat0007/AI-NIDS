# ============================================================
# AI-NIDS - Live Network Traffic Prediction Engine
# ============================================================

import os
import csv
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from scapy.all import sniff, IP, TCP, UDP


# ============================================================
# PATHS AND CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "src",
    "models",
    "nids_random_forest_cicids2017.pkl",
)

RESULTS_DIR = os.path.join(BASE_DIR, "results")
LOG_FILE = os.path.join(RESULTS_DIR, "detection_log.csv")

CAPTURE_SECONDS = 8


# ============================================================
# GLOBAL MODEL STATE
# ============================================================

model = None
MODEL_FEATURES = []
captured_packets = []


# ============================================================
# CREATE RESULTS DIRECTORY
# ============================================================

os.makedirs(RESULTS_DIR, exist_ok=True)


# ============================================================
# MODEL LOADING
# ============================================================

def load_model():
    """
    Load the trained CIC-IDS2017 Random Forest model.
    """

    global model
    global MODEL_FEATURES

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found:\n{MODEL_PATH}"
        )

    model = joblib.load(MODEL_PATH)

    print("=" * 60)
    print("AI-NIDS MODEL LOADED")
    print("=" * 60)
    print("Model: Random Forest")

    if not hasattr(model, "feature_names_in_"):
        raise RuntimeError(
            "The trained model does not contain feature_names_in_."
        )

    MODEL_FEATURES = list(model.feature_names_in_)

    print(
        f"Number of model features: {len(MODEL_FEATURES)}"
    )

    for index, feature in enumerate(
        MODEL_FEATURES,
        start=1,
    ):
        print(f"{index:02d}. {feature}")

    print("=" * 60)


# ============================================================
# PACKET CAPTURE
# ============================================================

def packet_handler(packet):
    """
    Store every captured packet.
    """

    captured_packets.append(packet)


def capture_network_traffic(seconds=CAPTURE_SECONDS):
    """
    Capture live network traffic for the specified duration.
    """

    global captured_packets

    captured_packets = []

    print()
    print("=" * 60)
    print("STARTING LIVE NETWORK CAPTURE")
    print("=" * 60)
    print(
        f"Capturing network traffic for {seconds} seconds..."
    )

    start_time = time.time()

    try:
        sniff(
            prn=packet_handler,
            store=False,
            timeout=seconds,
        )

    except Exception as error:
        print()
        print("PACKET CAPTURE ERROR")
        print("-" * 60)
        print(error)
        print("-" * 60)

        return [], 0.0

    elapsed = time.time() - start_time

    print(
        f"Packets captured: {len(captured_packets)}"
    )
    print(
        f"Capture duration: {elapsed:.2f} seconds"
    )

    return captured_packets, elapsed


# ============================================================
# SAFE NUMERIC FUNCTION
# ============================================================

def safe_number(value):
    """
    Convert a value to a safe finite float.
    """

    try:
        value = float(value)

        if np.isnan(value) or np.isinf(value):
            return 0.0

        return value

    except Exception:
        return 0.0


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(packets, duration):
    """
    Convert captured packets into the feature vector expected
    by the trained model.
    """

    packet_count = len(packets)

    if packet_count == 0:
        return {
            feature: 0.0
            for feature in MODEL_FEATURES
        }

    packet_sizes = []
    timestamps = []

    total_bytes = 0

    forward_packets = 0
    backward_packets = 0

    forward_bytes = 0
    backward_bytes = 0

    tcp_packets = 0
    udp_packets = 0

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0

    for packet in packets:
        try:
            if hasattr(packet, "time"):
                timestamps.append(float(packet.time))

            packet_length = len(packet)

            packet_sizes.append(packet_length)
            total_bytes += packet_length

            if IP in packet:
                source = packet[IP].src
                destination = packet[IP].dst

                if source <= destination:
                    forward_packets += 1
                    forward_bytes += packet_length
                else:
                    backward_packets += 1
                    backward_bytes += packet_length

            if TCP in packet:
                tcp_packets += 1

                flags = str(packet[TCP].flags)

                if "S" in flags:
                    syn_count += 1

                if "A" in flags:
                    ack_count += 1

                if "R" in flags:
                    rst_count += 1

                if "F" in flags:
                    fin_count += 1

            elif UDP in packet:
                udp_packets += 1

        except Exception:
            continue

    duration = max(float(duration), 0.001)

    average_packet_size = (
        total_bytes / packet_count
        if packet_count > 0
        else 0.0
    )

    flow_rate = total_bytes / duration
    packet_rate = packet_count / duration

    down_up_ratio = (
        backward_packets / forward_packets
        if forward_packets > 0
        else 0.0
    )

    fwd_packet_length_mean = (
        forward_bytes / forward_packets
        if forward_packets > 0
        else 0.0
    )

    bwd_packet_length_mean = (
        backward_bytes / backward_packets
        if backward_packets > 0
        else 0.0
    )

    fwd_iat_mean = 0.0
    bwd_iat_mean = 0.0

    if len(timestamps) > 1:
        timestamps.sort()

        intervals = np.diff(timestamps)

        if len(intervals) > 0:
            fwd_iat_mean = float(np.mean(intervals))

    feature_values = {
        "flow_duration": duration,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "fin_count": fin_count,
        "active_time": duration,
        "idle_time": 0.0,
        "header_length": packet_count * 20,
        "down_up_ratio": down_up_ratio,
        "fwd_iat_mean": fwd_iat_mean,
        "bwd_iat_mean": bwd_iat_mean,
        "fwd_packet_length": forward_bytes,
        "bwd_packet_length": backward_bytes,
        "flow_bytes": total_bytes,
        "flow_packets": packet_count,
        "flow_rate": flow_rate,
        "packet_rate": packet_rate,
        "avg_packet_size": average_packet_size,
        "total_fwd_packets": forward_packets,
        "total_bwd_packets": backward_packets,
        "fwd_packet_length_mean": fwd_packet_length_mean,
        "bwd_packet_length_mean": bwd_packet_length_mean,
        "syn_count": syn_count,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
    }

    final_features = {}

    for feature in MODEL_FEATURES:
        value = feature_values.get(feature, 0.0)
        final_features[feature] = safe_number(value)

    return final_features


# ============================================================
# RISK / SEVERITY
# ============================================================

def calculate_severity(prediction, confidence):
    """
    Calculate severity using the prediction and confidence.

    Prediction:
        0 = benign
        1 = attack

    Confidence:
        Expected range: 0.0 to 1.0
    """

    prediction = int(prediction)
    confidence = float(confidence)

    if prediction == 0:
        if confidence < 0.75:
            return "SUSPICIOUS"

        return "LOW"

    if confidence >= 0.80:
        return "HIGH"

    if confidence >= 0.50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SAVE DETECTION LOG
# ============================================================

def save_detection_log(
    prediction,
    confidence,
    severity,
    packet_count,
    duration,
):
    """
    Append one detection result to the CSV log.
    """

    file_exists = os.path.exists(LOG_FILE)

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(
                [
                    "timestamp",
                    "prediction",
                    "confidence",
                    "severity",
                    "packets_captured",
                    "capture_duration",
                ]
            )

        writer.writerow(
            [
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                int(prediction),
                round(float(confidence) * 100, 2),
                severity,
                packet_count,
                round(duration, 2),
            ]
        )


# ============================================================
# ML PREDICTION
# ============================================================

def predict_traffic(packets, duration):
    """
    Predict whether the captured traffic is benign or an attack.
    """

    if model is None:
        raise RuntimeError(
            "The model has not been loaded. "
            "Call load_model() first."
        )

    if not packets:
        print()
        print("No network packets captured.")

        return {
            "prediction": 0,
            "confidence": 0.0,
            "attack_probability": 0.0,
            "severity": "LOW",
            "packet_count": 0,
            "duration": duration,
        }

    features = extract_features(
        packets,
        duration,
    )

    X = pd.DataFrame(
        [features],
        columns=MODEL_FEATURES,
    )

    prediction = int(
        model.predict(X)[0]
    )

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        classes = list(model.classes_)

        confidence = float(np.max(probabilities))

        if 1 in classes:
            attack_probability = float(
                probabilities[classes.index(1)]
            )
        else:
            attack_probability = 0.0

    else:
        confidence = 0.0
        attack_probability = 0.0

    severity = calculate_severity(
        prediction,
        confidence,
    )

    print()
    print("=" * 60)
    print("AI-NIDS DETECTION RESULT")
    print("=" * 60)
    print(f"Packets Captured  : {len(packets)}")
    print(f"Prediction        : {prediction}")
    print(f"Confidence        : {confidence * 100:.2f}%")
    print(
        f"Attack Probability: "
        f"{attack_probability * 100:.2f}%"
    )
    print(f"Severity          : {severity}")

    if prediction == 1:
        print()
        print("RESULT: ATTACK DETECTED")
        print(
            "WARNING: Suspicious network traffic detected!"
        )

    elif severity == "SUSPICIOUS":
        print()
        print("RESULT: SUSPICIOUS TRAFFIC")
        print(
            "The model is uncertain about this traffic window."
        )

    else:
        print()
        print("RESULT: NORMAL TRAFFIC")
        print(
            "Network traffic appears normal."
        )

    print("=" * 60)

    save_detection_log(
        prediction=prediction,
        confidence=confidence,
        severity=severity,
        packet_count=len(packets),
        duration=duration,
    )

    print("Detection log saved to:")
    print(LOG_FILE)

    return {
    "prediction": prediction,
    "confidence": confidence,
    "attack_probability": attack_probability,
    "severity": severity,
    "packet_count": len(packets),
    "duration": duration,
    "features": features,
    }


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():
    load_model()

    print()
    print("AI-NIDS")
    print("AI-Based Network Intrusion Detection System")
    print()

    packets, duration = capture_network_traffic(
        CAPTURE_SECONDS
    )

    return predict_traffic(
        packets,
        duration,
    )


if __name__ == "__main__":
    main()