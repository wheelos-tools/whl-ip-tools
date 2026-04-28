# whl-ip-tools

IP protocol analysis toolkit — send, capture, and analyze network packets.

## Installation

```bash
pip install whl-ip-tools
```

Or install from source:

```bash
pip install -e .
```

## Usage

### send — Send binary data via UDP/TCP

```bash
# UDP client, send once
whl-ip-tools send -u 192.168.1.100:9090 -f frame.bin

# UDP client, 128-byte chunks, loop forever
whl-ip-tools send -u 192.168.1.100:9090 -f frame.bin --chunk 128 --loop

# TCP server, loop forever
whl-ip-tools send -t 0.0.0.0:9090 -f frame.bin --server --loop

# Send exactly 10 rounds with 0.1s interval
whl-ip-tools send -u 192.168.1.100:9090 -f frame.bin -n 10 -i 0.1
```

### view — Interactive TUI packet viewer

### dump — Dump received packets to a file

```bash
# UDP server, write to file
whl-ip-tools dump -u 0.0.0.0:9090 -o dump.bin --server

# TCP server
whl-ip-tools dump -t 0.0.0.0:9090 -o dump.bin --server

# UDP client (sends trigger byte, then receives)
whl-ip-tools dump -u 192.168.1.100:9090 -o dump.bin

# TCP client, append mode
whl-ip-tools dump -t 192.168.1.100:9090 -o dump.bin -a
```

### view — Interactive TUI packet viewer

```bash
# UDP server, hex mode
whl-ip-tools view -u 0.0.0.0:9090 --server

# TCP server with Kaitai Struct parser
whl-ip-tools view -t 0.0.0.0:9090 --server --kaitai ip_packet.py

# TCP client, force hex display
whl-ip-tools view -t 192.168.1.100:9090 --hex

# Multiple Kaitai parsers (tried in order)
whl-ip-tools view -u 0.0.0.0:9090 --server -k frame_a.py -k frame_b.py
```

#### Keybindings

| Key | Action |
|-----|--------|
| `j`/`k` | Move down/up |
| `h`/`l` | Collapse/expand tree node |
| `g`/`G` | Jump to top/bottom |
| `Ctrl-U`/`Ctrl-D` | Page up/down |
| `Tab` | Switch between list and detail pane |
| `Space`/`Enter` | Select row / toggle tree node |
| `s` | Switch display mode (hex ↔ kaitai) |
| `c` | Clear all packets |
| `q` | Quit |

## License

Apache License 2.0
