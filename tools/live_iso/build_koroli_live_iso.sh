#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root: sudo $0"
  exit 1
fi

for cmd in lb debootstrap xorriso; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Missing tool: $cmd"
    echo "Install with: sudo apt-get update && sudo apt-get install -y live-build debootstrap xorriso"
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/work"
OUT_DIR="$SCRIPT_DIR/out"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUT_DIR"

cp -r "$SCRIPT_DIR/config" "$WORK_DIR/"
cd "$WORK_DIR"

lb config \
  --mode debian \
  --distribution kali-rolling \
  --archive-areas "main contrib non-free non-free-firmware" \
  --binary-images iso-hybrid \
  --debian-installer false \
  --bootappend-live "boot=live components username=kali hostname=koroli-live quiet splash"

lb build

ISO_SRC="$(find . -maxdepth 2 -type f -name '*.iso' | head -n 1 || true)"
if [[ -z "$ISO_SRC" ]]; then
  echo "[ERROR] Build finished but no ISO found."
  exit 1
fi

cp "$ISO_SRC" "$OUT_DIR/koroli-live-python-gui.iso"
echo "[OK] ISO created: $OUT_DIR/koroli-live-python-gui.iso"
