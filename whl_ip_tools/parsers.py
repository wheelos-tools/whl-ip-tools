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

"""Packet display formatters: hex dump and Kaitai Struct parser."""

import enum
import importlib.util
import os
import sys
from typing import Optional

from rich.panel import Panel
from rich.tree import Tree


def format_hex_dump(data: bytes) -> Panel:
    """Format binary data as a classic hex dump panel."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(
            f"[dim]{offset:08x}[/dim]  {hex_left:<24s}  {hex_right:<24s}  "
            f"│[green]{ascii_repr}[/green]│"
        )
    return Panel(
        "\n".join(lines),
        title="Hex Dump",
        border_style="blue",
        padding=(0, 1),
    )


def load_kaitai_parser(path: str):
    """Load a Kaitai Struct parser class from a compiled Python file.

    Args:
        path: Path to a .py file containing a kaitaistruct.Struct subclass.

    Returns:
        The parser class.

    Raises:
        SystemExit: If kaitaistruct is not installed or no parser class found.
    """
    try:
        import kaitaistruct  # noqa: F401
    except ImportError:
        print(
            "Error: kaitaistruct is required for --kaitai. "
            "Install with: pip install kaitaistruct",
            file=sys.stderr,
        )
        sys.exit(1)

    path = os.path.abspath(path)
    dir_path = os.path.dirname(path)
    if dir_path not in sys.path:
        sys.path.insert(0, dir_path)

    spec = importlib.util.spec_from_file_location("kaitai_parser", path)
    if spec is None:
        print(f"Error: cannot load parser from {path}", file=sys.stderr)
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from kaitaistruct import KaitaiStruct

    for name in dir(module):
        obj = getattr(module, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, KaitaiStruct)
            and obj is not KaitaiStruct
        ):
            return obj

    print(
        f"Error: no KaitaiStruct subclass found in {path}",
        file=sys.stderr,
    )
    sys.exit(1)


def parse_kaitai(parser_class, data: bytes) -> Optional[Tree]:
    """Parse binary data with a Kaitai Struct parser and return a Rich Tree."""
    try:
        from io import BytesIO

        from kaitaistruct import KaitaiStream

        obj = parser_class(KaitaiStream(BytesIO(data)))
        tree = Tree(f"[bold]{parser_class.__name__}[/bold]")
        _build_tree(tree, obj)
        return tree
    except Exception:
        return None


def _build_tree(node: Tree, obj, depth: int = 0):
    """Recursively build a Rich Tree from a Kaitai Struct object."""
    from kaitaistruct import KaitaiStruct

    if depth > 20:
        node.add("[dim]... (max depth reached)[/dim]")
        return

    for attr in dir(obj):
        if attr.startswith("_") or attr in ("_read", "_io"):
            continue
        try:
            val = getattr(obj, attr)
        except Exception:
            continue
        if callable(val):
            continue

        if isinstance(val, (bytes, bytearray)):
            if len(val) > 32:
                node.add(f"{attr}: [dim]{val[:32].hex()}... ({len(val)}B)[/dim]")
            elif val:
                node.add(f"{attr}: {val.hex()}")
            else:
                node.add(f"{attr}: (empty)")
        elif isinstance(val, KaitaiStruct):
            branch = node.add(f"[bold]{attr}[/bold]:")
            _build_tree(branch, val, depth + 1)
        elif isinstance(val, list):
            branch = node.add(f"{attr}: [dim]{len(val)} items[/dim]")
            for i, item in enumerate(val[:50]):
                if isinstance(item, KaitaiStruct):
                    sub = branch.add(f"[{i}]")
                    _build_tree(sub, item, depth + 1)
                else:
                    branch.add(f"[{i}]: [green]{item}[/green]")
        elif isinstance(val, enum.Enum):
            node.add(f"{attr}: [cyan]{val}[/cyan]")
        else:
            node.add(f"{attr}: [green]{val}[/green]")
