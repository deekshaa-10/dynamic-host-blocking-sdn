#!/usr/bin/env python3
"""
metrics_client.py  —  Performance-measurement client for the Dynamic Host
Blocking System (CN Deliverable 2).

Acts like a legitimate user: it repeatedly opens a short TCP connection to the
server, sends one framed message, waits for the ACK, and records whether the
request SUCCEEDED and how long it took (latency). Results are written to a CSV.

Run this on a normal host (e.g. n1) DURING an attack, once with the SDN
controller protecting the network and once with the plain baseline switch.
Comparing the two CSVs shows how much the SDN protection helps legitimate users.

Usage:
    python3 metrics_client.py --server 10.0.0.4 --port 5000 \
            --duration 30 --interval 0.5 --out protected_n1.csv --label protected
"""

import argparse
import csv
import socket
import struct
import time

HEADER_SIZE = 4


def send_message(conn, payload: bytes):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exactly(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_message(conn):
    header = recv_exactly(conn, HEADER_SIZE)
    if header is None:
        return None
    (length,) = struct.unpack("!I", header)
    return recv_exactly(conn, length)


def one_request(server, port, timeout):
    """Return (success: bool, latency_seconds: float)."""
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))
        send_message(s, b"ping")
        reply = recv_message(s)
        s.close()
        latency = time.time() - start
        return (reply is not None), latency
    except Exception:
        return False, time.time() - start


def main():
    p = argparse.ArgumentParser(description="Performance-measurement client.")
    p.add_argument("--server", default="10.0.0.4")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--duration", type=float, default=30.0,
                   help="total seconds to run")
    p.add_argument("--interval", type=float, default=0.5,
                   help="seconds between requests")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="per-request timeout in seconds")
    p.add_argument("--out", default="metrics.csv", help="output CSV file")
    p.add_argument("--label", default="run",
                   help="scenario label stored in each row (e.g. protected/baseline)")
    args = p.parse_args()

    t0 = time.time()
    end = t0 + args.duration
    rows = []
    total = ok = 0

    while time.time() < end:
        success, latency = one_request(args.server, args.port, args.timeout)
        t_rel = round(time.time() - t0, 3)
        rows.append((args.label, t_rel, int(success), round(latency, 4)))
        total += 1
        ok += int(success)
        time.sleep(args.interval)

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "t_sec", "success", "latency_sec"])
        w.writerows(rows)

    rate = (100.0 * ok / total) if total else 0.0
    print(f"[{args.label}] requests={total} ok={ok} "
          f"success_rate={rate:.1f}%  -> {args.out}")


if __name__ == "__main__":
    main()
