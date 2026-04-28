# Copyright 2026 The WheelOS Team. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dump received packets to a file."""

import signal
import socket
import sys
import threading
import time
from typing import Optional, Tuple


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _parse_addr(addr_str: str) -> Tuple[str, int]:
    host, port = addr_str.rsplit(":", 1)
    return host, int(port)


_LOG_INTERVAL = 1.0  # seconds between progress logs


def _udp_recv_loop(
    sock: socket.socket, output_path: str, append: bool, stop: threading.Event
):
    mode = "ab" if append else "wb"
    total = 0
    pkt_count = 0
    last_log = 0.0
    with open(output_path, mode) as f:
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                f.write(data)
                total += len(data)
                pkt_count += 1
                now = time.monotonic()
                if now - last_log >= _LOG_INTERVAL:
                    log(f"{pkt_count} pkts, {total}B from {addr}")
                    last_log = now
            except (TimeoutError, OSError):
                continue
    log(f"done: {pkt_count} pkts, {total}B written to {output_path}")


def _tcp_recv_loop(
    sock: socket.socket, output_path: str, append: bool, stop: threading.Event
):
    mode = "ab" if append else "wb"
    total = 0
    pkt_count = 0
    last_log = 0.0
    with open(output_path, mode) as f:
        while not stop.is_set():
            try:
                data = sock.recv(65535)
                if not data:
                    break
                f.write(data)
                total += len(data)
                pkt_count += 1
                now = time.monotonic()
                if now - last_log >= _LOG_INTERVAL:
                    log(f"{pkt_count} pkts, {total}B")
                    last_log = now
            except (TimeoutError, OSError):
                continue
    log(f"done: {pkt_count} pkts, {total}B written to {output_path}")


def _udp_server(host: str, port: int, output_path: str, append: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind((host, port))
    log(f"UDP listening on {host}:{port}, writing to {output_path}")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: (stop.set(), sock.close()))

    _udp_recv_loop(sock, output_path, append, stop)
    stop.wait()


def _udp_client(host: str, port: int, output_path: str, append: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.sendto(b"\x00", (host, port))
    log(f"UDP client connected to {host}:{port}, writing to {output_path}")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: (stop.set(), sock.close()))

    _udp_recv_loop(sock, output_path, append, stop)
    stop.wait()


def _tcp_server(host: str, port: int, output_path: str, append: bool):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    srv.bind((host, port))
    srv.listen(5)
    log(f"TCP listening on {host}:{port}, writing to {output_path}")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: (stop.set(), srv.close()))

    mode = "ab" if append else "wb"
    total = 0
    pkt_count = 0
    last_log = 0.0
    with open(output_path, mode) as f:
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
            except (TimeoutError, OSError):
                continue
            log(f"client connected: {addr}")
            conn.settimeout(1.0)
            try:
                while not stop.is_set():
                    try:
                        data = conn.recv(65535)
                        if not data:
                            break
                        f.write(data)
                        total += len(data)
                        pkt_count += 1
                        now = time.monotonic()
                        if now - last_log >= _LOG_INTERVAL:
                            log(f"{pkt_count} pkts, {total}B from {addr}")
                            last_log = now
                    except TimeoutError:
                        continue
            finally:
                conn.close()
                log(f"client {addr} disconnected")

    log(f"done: {pkt_count} pkts, {total}B written to {output_path}")


def _tcp_client(host: str, port: int, output_path: str, append: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"Connection refused: {host}:{port}", file=sys.stderr)
        sys.exit(1)
    log(f"TCP connected to {host}:{port}, writing to {output_path}")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    _tcp_recv_loop(sock, output_path, append, stop)
    sock.close()


def run_dump(
    udp: Optional[str],
    tcp: Optional[str],
    output: str,
    append: bool,
    server: bool,
):
    if not udp and not tcp:
        print("Error: specify --udp or --tcp", file=sys.stderr)
        sys.exit(1)

    proto = "udp" if udp else "tcp"
    addr = udp or tcp
    assert addr is not None
    host, port = _parse_addr(addr)

    if proto == "udp":
        if server:
            _udp_server(host, port, output, append)
        else:
            _udp_client(host, port, output, append)
    else:
        if server:
            _tcp_server(host, port, output, append)
        else:
            _tcp_client(host, port, output, append)
