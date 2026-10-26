#!/usr/bin/env python3
"""Normal (well-behaved) TCP client for the Dynamic Host Blocking System."""

import argparse
import socket
import struct
import time

HEADER_SIZE = 4


def send_message(conn, payload):
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


def main():
    parser = argparse.ArgumentParser(description="Normal TCP client.")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--messages", type=int, default=5)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((args.server, args.port))
        print(f"Connected to {args.server}:{args.port}")
        for i in range(1, args.messages + 1):
            send_message(conn, f"hello {i}".encode("utf-8"))
            reply = recv_message(conn)
            if reply is None:
                print("Server closed the connection")
                break
            print(f"Sent #{i}, got: {reply.decode()}")
            time.sleep(args.interval)
    print("Done, connection closed cleanly")


if __name__ == "__main__":
    main()
