"""Emit one aggregated AI-NIDS result as JSON, from real captured packets."""

import json
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import conf, get_if_list, sniff  # noqa: E402

from src.detection import aggregate_detection_results, detect_packets  # noqa: E402
from src.inference import load_model  # noqa: E402

PORT = 8095


def serve(stop):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(8)
    server.settimeout(1.0)
    while not stop.is_set():
        try:
            connection, _ = server.accept()
            connection.recv(2048)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            connection.close()
        except Exception:
            continue
    server.close()


def main() -> int:
    model = load_model()
    loopback = [name for name in get_if_list() if "loopback" in name.lower()]
    stop = threading.Event()
    threading.Thread(target=serve, args=(stop,), daemon=True).start()
    time.sleep(0.5)

    def drive():
        time.sleep(1.0)
        for _ in range(6):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/d", timeout=2).read()
            except Exception:
                pass
            time.sleep(0.15)

    threading.Thread(target=drive, daemon=True).start()

    started = time.monotonic()
    packets = sniff(iface=loopback[0] if loopback else conf.iface,
                    filter=f"tcp port {PORT}", timeout=8, count=400)
    duration = round(time.monotonic() - started, 3)
    stop.set()

    if not packets:
        print(json.dumps({"error": "no packets captured"}))
        return 2

    aggregate = aggregate_detection_results(detect_packets(model, packets, capture_duration=duration))

    payload = {
        "prediction": int(aggregate["prediction"]),
        "confidence": float(aggregate["confidence"]),
        "attack_probability": float(aggregate["attack_probability"]),
        "severity": aggregate["severity"],
        "packet_count": int(aggregate["packet_count"]),
        "duration": float(aggregate["duration"]),
        "flow_count": len(aggregate["flows"]),
        "source": "captured loopback traffic (benign by construction)",
    }
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
