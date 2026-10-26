#!/usr/bin/env python3
"""Attacker client for the Dynamic Host Blocking System.

Opens TCP connections rapidly to simulate a suspicious host. Each new
connection is a new SYN with a fresh source port, which the SDN controller
counts per source IP. Crossing the threshold triggers a drop rule.
"""

import argparse
import socket
import struct
import time

HEADER_SIZE = 4


def send_message(conn, payload):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def conn_flood(server, port, rate, duration):
    interval = 1.0 / rate if rate > 0 else 0
    end = time.time() + duration
    count = 0
    while time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((server, port))
            count += 1
            try:
                send_message(s, b"x")
            except Exception:
                pass
            s.close()
        except Exception:
            pass
        if count % 20 == 0 and count > 0:
            print(f"opened {count} connections...")
        if interval:
            time.sleep(interval)
    print(f"conn-flood done: attempted ~{count} connections in {duration}s")


def data_flood(server, port, duration):
    end = time.time() + duration
    sent = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
        payload = b"A" * 1024
        while time.time() < end:
            send_message(s, payload)
            sent += 1
        s.close()
    except Exception as e:
        print(f"data-flood stopped: {e}")
    print(f"data-flood done: sent {sent} messages in {duration}s")


def main():
    parser = argparse.ArgumentParser(description="Attacker client (traffic generator).")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--mode", choices=["conn-flood", "data-flood"], default="conn-flood")
    parser.add_argument("--rate", type=int, default=50)
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()

    print(f"Attacking {args.server}:{args.port}  mode={args.mode}")
    if args.mode == "conn-flood":
        conn_flood(args.server, args.port, args.rate, args.duration)
    else:
        data_flood(args.server, args.port, args.duration)


if __name__ == "__main__":
    main()
