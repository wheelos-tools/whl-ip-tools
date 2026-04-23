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

"""Send binary data via UDP/TCP with configurable rounds and timing."""

import signal
import socket
import sys
import time


def parse_addr(addr_str: str) -> tuple[str, int]:
    host, port = addr_str.rsplit(":", 1)
    return host, int(port)


def load_data(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def chunk_data(data: bytes, size: int) -> list[bytes]:
    if size <= 0:
        return [data]
    return [data[i : i + size] for i in range(0, len(data), size)]


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def precise_sleep(target_interval: float, t_start: float):
    remaining = target_interval - (time.monotonic() - t_start)
    if remaining > 0:
        time.sleep(remaining)


def send_loop(
    sock, send_func, chunks: list[bytes], max_rounds: int, interval: float, label: str
):
    """Generic send loop.

    Args:
        max_rounds: 0 = infinite, >0 = exact number of rounds.
    """
    round_num = 0
    total_sent = 0
    t_round_start = time.monotonic()
    try:
        while True:
            round_num += 1
            for pkt in chunks:
                t0 = time.monotonic()
                send_func(pkt)
                total_sent += len(pkt)
                if interval > 0:
                    precise_sleep(interval, t0)
            elapsed = time.monotonic() - t_round_start
            # Log every 100 rounds, or the first/last round
            if round_num == 1 or round_num % 100 == 0:
                log(
                    f"round {round_num}: {len(chunks)} pkts, "
                    f"{total_sent}B total, {elapsed:.2f}s elapsed -> {label}"
                )
            if max_rounds > 0 and round_num >= max_rounds:
                break
    except KeyboardInterrupt:
        pass
    except (BrokenPipeError, ConnectionResetError, ConnectionRefusedError) as e:
        print(f"\nConnection error: {e}")
        return

    # Summary
    elapsed = time.monotonic() - t_round_start
    rate = total_sent / elapsed if elapsed > 0 else 0
    log(
        f"done: {round_num} rounds, {len(chunks)} pkts/round, "
        f"{total_sent}B total, {elapsed:.2f}s, {rate:.0f}B/s -> {label}"
    )


# ── UDP ──────────────────────────────────────────────────────────────


def udp_client(
    host: str, port: int, chunks: list[bytes], max_rounds: int, interval: float
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_loop(
            sock,
            lambda pkt: sock.sendto(pkt, (host, port)),
            chunks,
            max_rounds,
            interval,
            f"{host}:{port}",
        )
    finally:
        sock.close()


def udp_server(
    host: str, port: int, chunks: list[bytes], max_rounds: int, interval: float
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    log(f"UDP listening on {host}:{port}, waiting for client...")

    signal.signal(
        signal.SIGINT,
        lambda *_: (sock.close(), print("\nStopped."), sys.exit(0)),
    )

    while True:
        _, client_addr = sock.recvfrom(65535)
        log(f"Client discovered: {client_addr}")
        try:
            send_loop(
                sock,
                lambda pkt, _addr=client_addr: sock.sendto(pkt, _addr),
                chunks,
                max_rounds,
                interval,
                str(client_addr),
            )
        except (BrokenPipeError, OSError):
            log(f"Client {client_addr} send failed, waiting for new client...")
            continue
        if max_rounds > 0:
            break


# ── TCP ──────────────────────────────────────────────────────────────


def tcp_client(
    host: str, port: int, chunks: list[bytes], max_rounds: int, interval: float
):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        try:
            send_loop(
                sock,
                lambda pkt: sock.sendall(pkt),
                chunks,
                max_rounds,
                interval,
                f"{host}:{port}",
            )
        finally:
            sock.close()
    except ConnectionRefusedError:
        print(f"Connection refused: {host}:{port}", file=sys.stderr)
        sys.exit(1)


def tcp_server(
    host: str, port: int, chunks: list[bytes], max_rounds: int, interval: float
):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    log(f"TCP listening on {host}:{port}...")

    signal.signal(
        signal.SIGINT,
        lambda *_: (server_sock.close(), print("\nStopped."), sys.exit(0)),
    )

    while True:
        conn, addr = server_sock.accept()
        log(f"Client connected: {addr}")
        try:
            send_loop(
                conn,
                lambda pkt, _c=conn: _c.sendall(pkt),
                chunks,
                max_rounds,
                interval,
                str(addr),
            )
        except (BrokenPipeError, ConnectionResetError):
            print(f"\nClient {addr} disconnected.")
        finally:
            conn.close()
        if max_rounds > 0:
            break


# ── Entry ────────────────────────────────────────────────────────────


def run_send(
    udp: str | None,
    tcp: str | None,
    file_path: str,
    chunk: int,
    loop: bool,
    interval: float,
    count: int | None,
    server: bool,
):
    if not udp and not tcp:
        print("Error: specify --udp or --tcp", file=sys.stderr)
        sys.exit(1)

    data = load_data(file_path)
    if not data:
        print("Error: no data to send", file=sys.stderr)
        sys.exit(1)

    chunks = chunk_data(data, chunk)

    # Determine max rounds: --count overrides --loop
    if count is not None:
        max_rounds = count
    elif loop:
        max_rounds = 0  # infinite
    else:
        max_rounds = 1

    if udp:
        host, port = parse_addr(udp)  # type: ignore[arg-type]
        if server:
            udp_server(host, port, chunks, max_rounds, interval)
        else:
            udp_client(host, port, chunks, max_rounds, interval)
    else:
        host, port = parse_addr(tcp)  # type: ignore[arg-type]
        if server:
            tcp_server(host, port, chunks, max_rounds, interval)
        else:
            tcp_client(host, port, chunks, max_rounds, interval)
