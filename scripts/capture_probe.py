"""Probe whether this machine can capture packets for a live-flow assessment."""

import socket
import sys
import threading
import time
import urllib.request

from scapy.all import conf, get_if_list, sniff

print("scapy ifaces:")
for name in get_if_list():
    print("  ", name)

loopback = [name for name in get_if_list() if "loopback" in name.lower() or "lo" == name.lower()]
print("loopback candidates:", loopback)


def serve():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8098))
    server.listen(5)
    server.settimeout(8)
    try:
        while True:
            connection, _ = server.accept()
            connection.recv(1024)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            connection.close()
    except Exception:
        pass
    finally:
        server.close()


threading.Thread(target=serve, daemon=True).start()
time.sleep(0.5)

captured = []


def driver():
    time.sleep(1.0)
    for _ in range(5):
        try:
            urllib.request.urlopen("http://127.0.0.1:8098/data", timeout=2).read()
        except Exception:
            pass
        time.sleep(0.2)


threading.Thread(target=driver, daemon=True).start()

interface = loopback[0] if loopback else conf.iface
print("capturing on:", interface)

try:
    packets = sniff(iface=interface, filter="tcp port 8098", timeout=8, count=50)
    print("captured packets:", len(packets))
    if packets:
        print("first summary:", packets[0].summary())
        print("protocols:", {p.summary().split()[0] for p in packets[:5]})
except Exception as exc:
    print("CAPTURE FAILED:", type(exc).__name__, str(exc)[:200])
    sys.exit(2)

sys.exit(0 if packets else 1)
