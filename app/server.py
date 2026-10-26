#!/usr/bin/env python3
"""Multithreaded TCP server for the Dynamic Host Blocking System."""

import argparse
import logging
import os
import socket
import struct
import threading

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
HEADER_SIZE = 4
MAX_MSG_SIZE = 65536

active_lock = threading.Lock()
active_clients = 0


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("logs/server.log")],
    )


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
    if length == 0 or length > MAX_MSG_SIZE:
        return None
    return recv_exactly(conn, length)


def send_message(conn, payload):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def handle_client(conn, addr):
    global active_clients
    with active_lock:
        active_clients += 1
        current = active_clients
    logging.info(f"CONNECT    {addr[0]}:{addr[1]}  (active clients: {current})")

    msg_count = 0
    try:
        while True:
            msg = recv_message(conn)
            if msg is None:
                break
            msg_count += 1
            text = msg.decode("utf-8", errors="replace")
            logging.info(f"MESSAGE    {addr[0]}:{addr[1]}  #{msg_count}: {text!r}")
            send_message(conn, f"ACK {msg_count}".encode("utf-8"))
    except ConnectionResetError:
        logging.info(f"RESET      {addr[0]}:{addr[1]}  (client dropped)")
    except Exception as e:
        logging.info(f"ERROR      {addr[0]}:{addr[1]}  {e}")
    finally:
        conn.close()
        with active_lock:
            active_clients -= 1
            remaining = active_clients
        logging.info(
            f"DISCONNECT {addr[0]}:{addr[1]}  "
            f"(messages: {msg_count}, active clients: {remaining})"
        )


def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP server.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    setup_logging()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(128)
    logging.info(f"SERVER     listening on {args.host}:{args.port}")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logging.info("SERVER     shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
