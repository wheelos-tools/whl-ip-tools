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

"""CLI entry point: whl-ip-tools send / view."""

import typer

app = typer.Typer(
    name="whl-ip-tools",
    help="IP protocol analysis toolkit — send, capture, and analyze network packets.",
    no_args_is_help=True,
)


@app.command()
def send(
    udp: str | None = typer.Option(
        None,
        "--udp",
        "-u",
        metavar="HOST:PORT",
        help="UDP target/bind address",
    ),
    tcp: str | None = typer.Option(
        None,
        "--tcp",
        "-t",
        metavar="HOST:PORT",
        help="TCP target/bind address",
    ),
    file: str = typer.Option(
        "-",
        "--file",
        "-f",
        help="Binary file to send (- for stdin)",
    ),
    chunk: int = typer.Option(
        0,
        "--chunk",
        metavar="N",
        help="Split data into N-byte chunks (0 = whole file)",
    ),
    loop: bool = typer.Option(
        False,
        "--loop",
        "-l",
        help="Repeat indefinitely",
    ),
    interval: float = typer.Option(
        0.1,
        "--interval",
        "-i",
        metavar="SEC",
        help="Delay between chunks in seconds (default: 0.1)",
    ),
    count: int | None = typer.Option(
        None,
        "--count",
        "-n",
        metavar="N",
        help="Number of send rounds (overrides --loop)",
    ),
    server: bool = typer.Option(
        False,
        "--server",
        help="Server mode: bind and wait for client",
    ),
):
    """Send binary data via UDP/TCP."""
    from .sender import run_send

    run_send(
        udp=udp,
        tcp=tcp,
        file_path=file,
        chunk=chunk,
        loop=loop,
        interval=interval,
        count=count,
        server=server,
    )


@app.command()
def dump(
    udp: str | None = typer.Option(
        None,
        "--udp",
        "-u",
        metavar="HOST:PORT",
        help="UDP bind/connect address",
    ),
    tcp: str | None = typer.Option(
        None,
        "--tcp",
        "-t",
        metavar="HOST:PORT",
        help="TCP bind/connect address",
    ),
    output: str = typer.Option(
        "dump.bin",
        "--output",
        "-o",
        metavar="FILE",
        help="Output file path (default: dump.bin)",
    ),
    append: bool = typer.Option(
        False,
        "--append",
        "-a",
        help="Append to output file instead of overwriting",
    ),
    server: bool = typer.Option(
        False,
        "--server",
        help="Server mode (listen for connections)",
    ),
):
    """Dump received packets to a file."""
    from .dumper import run_dump

    run_dump(
        udp=udp,
        tcp=tcp,
        output=output,
        append=append,
        server=server,
    )


@app.command()
def view(
    udp: str | None = typer.Option(
        None,
        "--udp",
        "-u",
        metavar="HOST:PORT",
        help="UDP bind/connect address",
    ),
    tcp: str | None = typer.Option(
        None,
        "--tcp",
        "-t",
        metavar="HOST:PORT",
        help="TCP bind/connect address",
    ),
    server: bool = typer.Option(
        False,
        "--server",
        help="Server mode (listen for connections)",
    ),
    hex_mode: bool = typer.Option(
        False,
        "--hex",
        help="Start in hex display mode (press s in TUI to switch)",
    ),
    kaitai: list[str] | None = typer.Option(
        None,
        "--kaitai",
        "-k",
        metavar="PATH",
        help="Compiled Kaitai Struct parser (can specify multiple, tried in order)",
    ),
    frame_id_bytes: int = typer.Option(
        4,
        "--frame-id-bytes",
        metavar="N",
        help=(
            "Number of leading bytes used as frame ID"
            " for dedup in hex mode (default: 4)"
        ),
    ),
):
    """Interactive packet viewer with TUI."""
    from .viewer import run_viewer

    run_viewer(
        udp=udp,
        tcp=tcp,
        server=server,
        hex_mode=hex_mode,
        kaitai=kaitai,
        frame_id_bytes=frame_id_bytes,
    )
