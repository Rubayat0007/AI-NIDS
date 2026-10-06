"""Live packet capture boundary for the NIDS application."""

import time

from scapy.all import sniff


CAPTURE_SECONDS = 8


def capture_network_traffic(seconds=CAPTURE_SECONDS):
    """Capture live network traffic for the specified duration."""
    packets = []

    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise TypeError("seconds must be numeric") from exc

    if duration < 0:
        raise ValueError("seconds must be non-negative")

    start_time = time.time()

    try:
        sniff(
            prn=packets.append,
            store=False,
            timeout=duration,
        )
    except Exception:
        return [], 0.0

    elapsed = time.time() - start_time

    return packets, elapsed