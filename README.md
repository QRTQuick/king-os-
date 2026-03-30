# KOROLI OS (КОРОЛИ)

Green-on-black hobby OS written in C and Assembly, with a simple GUI scanner and automatic text fallback.

## Features

- Multiboot boot via GRUB
- 32-bit kernel entry in Assembly
- VGA text-mode terminal fallback (green on black)
- Simple framebuffer GUI scanner (green/black)
- Automatic text-mode fallback when framebuffer is unavailable
- GUI logic written in C with assembly-optimized fill routines for faster drawing
- Interrupt core linked with assembly: IDT load, IRQ stubs, PIT timer, keyboard IRQ
- Basic CLI shell fallback
- URL/API heuristic safety checks (`scan`, `apitest`)
- Host-side networking audit helper (`tools/net_audit.sh`)

## Build

```bash
make
```

Output ISO:

- `build/koroli-os.iso`

## Run

```bash
make run
```

In GRUB menu:
- `КОРОЛИ OS SIMPLE UI (Kings)` for GUI when available
- `КОРОЛИ OS TEXT (fallback)` for text mode

## Python Desktop GUI (XP/Vista Style)

For a full responsive, network-enabled desktop app on Kali/Linux:

```bash
make run-py-gui
```

or:

```bash
python3 tools/gui/koroli_desktop_gui.py
```

Features:
- threaded scanning (non-blocking UI)
- website and API scan modes
- DNS, HTTP, TLS info
- risk scoring + verdict panel

## Linux ISO With Python GUI (Option 2)

Build a Linux live ISO that auto-starts the Python desktop GUI:

```bash
cd /home/chisomlifeeke/Desktop/king-os-
make build-linux-py-iso
```

Output ISO path:

- `tools/live_iso/out/koroli-live-python-gui.iso`

## GUI Controls

- `1` = Website scan mode
- `2` = API test mode
- `Tab` = switch scan mode
- Type URL/API target in input field
- `Enter` = run scan
- `Backspace` = delete input
- `Esc` = clear input/results

## Notes

The scanner in GUI mode is heuristic/offline. Real live network calls inside bare-metal kernel require NIC drivers + TCP/IP stack, which are future phases.

See `docs/INTERNET_TOOLS.md` for online references and tooling.
