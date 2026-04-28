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

"""Interactive TUI packet viewer with dedup and collapsible tree display."""

import contextlib
import enum
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static, Tree

from .parsers import load_kaitai_parser

DETAIL_REFRESH = 0.05  # seconds between detail tree rebuilds
TABLE_REFRESH = 0.05  # seconds between table rebuilds


def _node_key(label_plain: str) -> str:
    """Extract key part from a node label — the part before ': '."""
    if ": " in label_plain:
        return label_plain.split(": ", 1)[0]
    return label_plain


@dataclass
class PacketEntry:
    data: bytes
    addr: tuple
    parser_class: Optional[type] = None  # which kaitai parser matched (cached)
    count: int = 1
    total_bytes: int = 0
    first_time: float = field(default_factory=time.time)
    last_time: float = field(default_factory=time.time)


class PacketViewer(App):
    """TUI viewer with vim-style keybindings and multi-parser support."""

    BINDINGS = [
        # Vim navigation
        Binding("j", "vim_down", "Down", show=False),
        Binding("k", "vim_up", "Up", show=False),
        Binding("h", "vim_collapse", "Collapse", show=False),
        Binding("l", "vim_expand", "Expand", show=False),
        Binding("g", "vim_home", "Top", show=False),
        Binding("G", "vim_end", "Bottom", show=False),
        Binding("ctrl+u", "vim_page_up", "Page Up", show=False),
        Binding("ctrl+d", "vim_page_down", "Page Down", show=False),
        Binding("space", "vim_toggle", "Toggle", show=False),
        Binding("enter", "vim_select", "Select", show=False),
        Binding("tab", "switch_pane", "Pane", show=False),
        Binding("s", "cycle_mode", "Switch Mode"),
        # Actions
        Binding("q", "quit", "Quit"),
        Binding("c", "clear_packets", "Clear"),
    ]

    CSS = """
    Horizontal {
        height: 1fr;
    }
    #left-pane {
        width: 2fr;
        border: solid $primary;
    }
    #right-pane {
        width: 3fr;
        border: solid $primary;
    }
    #status {
        dock: bottom;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 2;
    }
    DataTable {
        height: 1fr;
    }
    #detail {
        height: 1fr;
    }
    """

    def __init__(
        self,
        proto: str,
        host: str,
        port: int,
        server: bool,
        hex_mode: bool,
        kaitai_parsers: Optional[List[type]] = None,
        frame_id_bytes: int = 4,
    ):
        super().__init__()
        self.proto = proto
        self.host = host
        self.port = port
        self.server_mode = server
        self.kaitai_parsers = kaitai_parsers or []
        self.frame_id_bytes = frame_id_bytes
        self._running = True

        # Display modes: hex always available, kaitai added when any parser loaded
        self.display_modes: List[str] = ["hex"]
        if self.kaitai_parsers:
            self.display_modes.insert(0, "kaitai")
        self.active_display = "hex" if hex_mode else self.display_modes[0]

        self.packets: Dict[str, PacketEntry] = {}
        self.selected_key: Optional[str] = None
        self.total_packets = 0
        self.total_bytes = 0
        self._last_detail_update = 0.0
        self._last_table_update = 0.0
        self._expanded_paths: Set[Tuple[str, ...]] = set()

    # ── Compose & mount ─────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="left-pane"):
                yield DataTable(id="msg-list")
            with Vertical(id="right-pane"):
                yield Tree("Select a message", id="detail")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        mode = "Server" if self.server_mode else "Client"
        self.title = f"whl-ip-tools — {self.proto.upper()} {mode}"
        self.sub_title = f"{self.host}:{self.port}"

        self.query_one("#left-pane").border_title = "Messages"
        self._update_mode_title()

        table = self.query_one("#msg-list", DataTable)
        table.add_column("Type", key="type")
        table.add_column("Count", key="count")
        table.add_column("Rate", key="rate")
        table.add_column("Size", key="size")
        table.add_column("Last", key="last")
        table.add_column("From", key="from")
        table.cursor_type = "row"

        self.query_one("#msg-list").focus()
        self.run_worker(self._network_worker, thread=True)

    def on_unmount(self) -> None:
        self._running = False

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key.value)
        if key in self.packets:
            self.selected_key = key
            self._rebuild_detail(self.packets[key])

    # ── Vim key actions ─────────────────────────────────────────────

    def _current_pane(self) -> str:
        focused = self.focused
        if focused and focused.id == "msg-list":
            return "list"
        return "detail"

    def action_vim_down(self) -> None:
        f = self.focused
        if f and hasattr(f, "action_cursor_down"):
            f.action_cursor_down()

    def action_vim_up(self) -> None:
        f = self.focused
        if f and hasattr(f, "action_cursor_up"):
            f.action_cursor_up()

    def action_vim_collapse(self) -> None:
        tree = self.query_one("#detail", Tree)
        if self.focused is tree:
            node = tree.cursor_node
            if node:
                node.collapse()

    def action_vim_expand(self) -> None:
        tree = self.query_one("#detail", Tree)
        if self.focused is tree:
            node = tree.cursor_node
            if node:
                node.expand()

    def action_vim_page_up(self) -> None:
        f = self.focused
        if f and hasattr(f, "action_page_up"):
            f.action_page_up()

    def action_vim_page_down(self) -> None:
        f = self.focused
        if f and hasattr(f, "action_page_down"):
            f.action_page_down()

    def action_vim_toggle(self) -> None:
        tree = self.query_one("#detail", Tree)
        if self.focused is tree:
            if hasattr(tree, "action_toggle_node"):
                tree.action_toggle_node()
        else:
            self._select_current_row()

    def action_vim_select(self) -> None:
        if self._current_pane() == "list":
            self._select_current_row()
        else:
            tree = self.query_one("#detail", Tree)
            if hasattr(tree, "action_toggle_node"):
                tree.action_toggle_node()

    def action_vim_home(self) -> None:
        if self._current_pane() == "list":
            table = self.query_one("#msg-list", DataTable)
            with contextlib.suppress(Exception):
                table.move_cursor(row=0)
        else:
            tree = self.query_one("#detail", Tree)
            if hasattr(tree, "action_scroll_home"):
                tree.action_scroll_home()

    def action_vim_end(self) -> None:
        if self._current_pane() == "list":
            table = self.query_one("#msg-list", DataTable)
            with contextlib.suppress(Exception):
                table.move_cursor(row=max(len(self.packets) - 1, 0))
        else:
            tree = self.query_one("#detail", Tree)
            if hasattr(tree, "action_scroll_end"):
                tree.action_scroll_end()

    def action_switch_pane(self) -> None:
        if self._current_pane() == "list":
            self.query_one("#detail", Tree).focus()
        else:
            self.query_one("#msg-list", DataTable).focus()

    def action_cycle_mode(self) -> None:
        """Switch display mode: hex ↔ kaitai (↔ future parsers)."""
        idx = self.display_modes.index(self.active_display)
        self.active_display = self.display_modes[(idx + 1) % len(self.display_modes)]
        self._update_mode_title()
        if self.selected_key and self.selected_key in self.packets:
            self._save_tree_state()
            self._rebuild_detail(self.packets[self.selected_key])
            self._restore_tree_state()

    def _update_mode_title(self) -> None:
        modes_str = "/".join(
            m.upper() if m == self.active_display else m for m in self.display_modes
        )
        self.query_one("#right-pane").border_title = f"Detail [{modes_str}]"

    def _select_current_row(self) -> None:
        table = self.query_one("#msg-list", DataTable)
        try:
            row_index = table.cursor_row
        except Exception:
            return
        keys = list(self.packets.keys())
        if 0 <= row_index < len(keys):
            self.selected_key = keys[row_index]
            self._rebuild_detail(self.packets[self.selected_key])

    # ── Multi-parser matching ───────────────────────────────────────

    def _match_parser(self, data: bytes) -> type | None:
        """Try each kaitai parser in order, return first that succeeds."""
        for parser_cls in self.kaitai_parsers:
            try:
                from io import BytesIO

                from kaitaistruct import KaitaiStream

                parser_cls(KaitaiStream(BytesIO(data)))
                return parser_cls
            except Exception:
                continue
        return None

    # ── Network I/O (threaded) ──────────────────────────────────────

    @work(thread=True)
    def _network_worker(self) -> None:
        try:
            if self.proto == "udp":
                self._udp_worker()
            else:
                self._tcp_worker()
        except Exception as exc:
            self.call_from_thread(self._log_error, str(exc))

    def _udp_worker(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            if self.server_mode:
                sock.bind((self.host, self.port))
            else:
                sock.sendto(b"\x00", (self.host, self.port))
            while self._running:
                try:
                    data, addr = sock.recvfrom(65535)
                    self.call_from_thread(self._on_packet, data, addr)
                except TimeoutError:
                    continue
        finally:
            sock.close()

    def _tcp_worker(self) -> None:
        if self.server_mode:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(1.0)
            srv.bind((self.host, self.port))
            srv.listen(5)
            try:
                while self._running:
                    try:
                        conn, addr = srv.accept()
                        threading.Thread(
                            target=self._handle_tcp_conn,
                            args=(conn, addr),
                            daemon=True,
                        ).start()
                    except TimeoutError:
                        continue
            finally:
                srv.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            try:
                sock.connect((self.host, self.port))
                while self._running:
                    try:
                        data = sock.recv(65535)
                        if not data:
                            break
                        self.call_from_thread(
                            self._on_packet, data, (self.host, self.port)
                        )
                    except TimeoutError:
                        continue
            except ConnectionRefusedError:
                self.call_from_thread(
                    self._log_error, f"Connection refused: {self.host}:{self.port}"
                )
            finally:
                sock.close()

    def _handle_tcp_conn(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(1.0)
        try:
            while self._running:
                try:
                    data = conn.recv(65535)
                    if not data:
                        break
                    self.call_from_thread(self._on_packet, data, addr)
                except TimeoutError:
                    continue
        finally:
            conn.close()

    # ── Packet dedup & display ──────────────────────────────────────

    def _get_packet_key(self, data: bytes, matched_parser: Optional[type]) -> str:
        if matched_parser:
            return matched_parser.__name__
        n = self.frame_id_bytes
        return f"hex:{data[:n].hex()}"

    def _on_packet(self, data: bytes, addr: tuple) -> None:
        self.total_packets += 1
        self.total_bytes += len(data)

        # Try match parser (only for new keys; cached in entry for existing)
        matched = self._match_parser(data) if self.kaitai_parsers else None
        key = self._get_packet_key(data, matched)

        if key in self.packets:
            entry = self.packets[key]
            entry.count += 1
            entry.total_bytes += len(data)
            entry.last_time = time.time()
            entry.data = data
            entry.addr = addr
        else:
            entry = PacketEntry(
                data=data,
                addr=addr,
                parser_class=matched,
                total_bytes=len(data),
            )
            self.packets[key] = entry
            if self.selected_key is None:
                self.selected_key = key

        now = time.time()

        # Throttle table rebuilds
        if now - self._last_table_update > TABLE_REFRESH:
            self._refresh_table()
            self._last_table_update = now

        # Throttle detail tree rebuilds (preserving expand state)
        if key == self.selected_key and now - self._last_detail_update > DETAIL_REFRESH:
            self._save_tree_state()
            self._rebuild_detail(entry)
            self._restore_tree_state()
            self._last_detail_update = now

        self._update_status()

    def _refresh_table(self) -> None:
        """Clear and rebuild the message summary table."""
        table = self.query_one("#msg-list", DataTable)
        try:
            cursor_row = table.cursor_row
        except Exception:
            cursor_row = 0

        table.clear()
        for k, entry in self.packets.items():
            elapsed = max(time.time() - entry.first_time, 0.001)
            rate = entry.count / elapsed
            ts = time.strftime("%H:%M:%S", time.localtime(entry.last_time))

            sel = k == self.selected_key
            style = "bold cyan" if sel else ""
            prefix = "▸ " if sel else "  "

            table.add_row(
                Text(f"{prefix}{k}", style=style),
                Text(str(entry.count), style=style),
                Text(f"{rate:.1f}/s", style=style),
                Text(f"{len(entry.data)}B", style=style),
                Text(ts, style=style),
                Text(f"{entry.addr[0]}:{entry.addr[1]}", style=style),
                key=k,
            )

        # Preserve user's cursor position
        if cursor_row < len(self.packets):
            with contextlib.suppress(Exception):
                table.move_cursor(row=cursor_row)

    # ── Tree state persistence ──────────────────────────────────────

    def _save_tree_state(self) -> None:
        """Walk the detail tree and remember which node paths are expanded."""
        expanded: Set[Tuple[str, ...]] = set()

        def walk(node, path: Tuple[str, ...]):
            for child in node.children:
                label = (
                    child.label.plain
                    if hasattr(child.label, "plain")
                    else str(child.label)
                )
                key = _node_key(label)
                child_path = path + (key,)
                if getattr(child, "is_expanded", False):
                    expanded.add(child_path)
                walk(child, child_path)

        tree = self.query_one("#detail", Tree)
        walk(tree.root, ())
        self._expanded_paths = expanded

    def _restore_tree_state(self) -> None:
        """Re-apply saved expand state onto the newly built tree."""
        saved = self._expanded_paths
        if not saved:
            return

        def walk(node, path: Tuple[str, ...]):
            for child in node.children:
                label = (
                    child.label.plain
                    if hasattr(child.label, "plain")
                    else str(child.label)
                )
                key = _node_key(label)
                child_path = path + (key,)
                if child_path in saved:
                    child.expand()
                walk(child, child_path)

        tree = self.query_one("#detail", Tree)
        walk(tree.root, ())

    # ── Detail tree ─────────────────────────────────────────────────

    def _rebuild_detail(self, entry: PacketEntry) -> None:
        tree = self.query_one("#detail", Tree)
        tree.clear()

        if self.active_display == "kaitai" and entry.parser_class:
            try:
                from io import BytesIO

                from kaitaistruct import KaitaiStream

                obj = entry.parser_class(KaitaiStream(BytesIO(entry.data)))
                tree.root.set_label(entry.parser_class.__name__)
                self._build_tree(tree.root, obj)
                tree.root.expand()
                return
            except Exception:
                pass

        # Hex (always available, also serves as fallback)
        tree.root.set_label("Hex Dump")
        data = entry.data
        for offset in range(0, min(len(data), 512), 16):
            chunk = data[offset : offset + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            tree.root.add(f"[dim]{offset:08x}[/dim]  {hex_str:<48s}  {ascii_str}")
        if len(data) > 512:
            tree.root.add(f"... ({len(data) - 512} more bytes)")
        tree.root.expand()

    def _build_tree(self, node, obj, depth: int = 0) -> None:
        from kaitaistruct import KaitaiStruct

        if depth > 20:
            node.add("[dim]... (max depth)[/dim]")
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
                hex_str = val[:16].hex()
                suffix = f"... ({len(val)}B)" if len(val) > 16 else ""
                node.add(f"{attr}: {hex_str}{suffix}")
            elif isinstance(val, KaitaiStruct):
                sub = node.add(f"{attr}")
                self._build_tree(sub, val, depth + 1)
            elif isinstance(val, list):
                sub = node.add(f"{attr} [{len(val)}]")
                for i, item in enumerate(val[:50]):
                    if isinstance(item, KaitaiStruct):
                        item_node = sub.add(f"[{i}]")
                        self._build_tree(item_node, item, depth + 1)
                    else:
                        sub.add(f"[{i}]: {item}")
            elif isinstance(val, enum.Enum):
                node.add(f"{attr}: [cyan]{val.name}[/cyan]")
            else:
                node.add(f"{attr}: [green]{val}[/green]")

    # ── UI helpers ──────────────────────────────────────────────────

    def _log_error(self, msg: str) -> None:
        self.query_one("#detail", Tree).root.set_label(f"[red]Error: {msg}[/red]")

    def _update_status(self) -> None:
        self.query_one("#status", Static).update(
            f" Packets: {self.total_packets} | Bytes: {self.total_bytes}"
        )

    def action_clear_packets(self) -> None:
        self.packets.clear()
        self.selected_key = None
        self.total_packets = 0
        self.total_bytes = 0
        self._expanded_paths.clear()
        self.query_one("#msg-list", DataTable).clear()
        tree = self.query_one("#detail", Tree)
        tree.clear()
        tree.root.set_label("Select a message")
        self._update_status()


def run_viewer(
    udp: Optional[str],
    tcp: Optional[str],
    server: bool,
    hex_mode: bool,
    kaitai: Optional[List[str]],
    frame_id_bytes: int = 4,
):
    """Entry point for the view subcommand."""
    if not udp and not tcp:
        print("Error: specify --udp or --tcp", file=sys.stderr)
        sys.exit(1)

    proto = "udp" if udp else "tcp"
    addr = udp or tcp
    assert addr is not None
    host, port = addr.rsplit(":", 1)
    port = int(port)

    kaitai_parsers = []
    if kaitai:
        for path in kaitai:
            kaitai_parsers.append(load_kaitai_parser(path))

    app = PacketViewer(
        proto=proto,
        host=host,
        port=port,
        server=server,
        hex_mode=hex_mode,
        kaitai_parsers=kaitai_parsers if kaitai_parsers else None,
        frame_id_bytes=frame_id_bytes,
    )
    app.run()
