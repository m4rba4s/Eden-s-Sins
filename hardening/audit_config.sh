#!/usr/bin/env bash
# ============================================================
# CIS Benchmark Audit — The Eden's Sins Hardening
# Automated check against CIS Apple macOS Benchmark v3.0
#
# Usage: bash audit_config.sh [--dry-run] [--json]
# ============================================================
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0

check() {
    local id="$1" desc="$2" cmd="$3" expected="$4"
    result=$(eval "$cmd" 2>/dev/null || echo "ERROR")
    if echo "$result" | grep -qi "$expected"; then
        echo -e "  ${GREEN}[PASS]${NC} ${id}: ${desc}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} ${id}: ${desc}"
        echo -e "         Got: ${result:0:80}"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — CIS macOS Benchmark Audit  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Not macOS. Showing CIS Benchmark checklist:"
    echo ""
    echo "  1.1  Verify all Apple-provided software is current"
    echo "  1.2  Enable Auto Update"
    echo "  1.3  Enable app update installs"
    echo "  2.1  Enable Gatekeeper"
    echo "  2.2  Enable Firewall"
    echo "  2.3  Enable Firewall Stealth Mode"
    echo "  2.4  Disable Remote Apple Events"
    echo "  2.5  Disable Remote Login (SSH)"
    echo "  2.6  Disable Screen Sharing"
    echo "  2.7  Enable FileVault"
    echo "  2.8  Enable SIP"
    echo "  3.1  Set screen saver lock < 5min"
    echo "  3.2  Require password after sleep/screensaver"
    echo "  4.1  Disable Safari auto-open"
    echo "  5.1  Disable root login"
    echo "  5.2  Reduce sudo timeout"
    echo "  5.3  Disable guest account"
    echo "  6.1  Enable audit logging"
    echo "  6.2  Configure audit flags"
    echo ""
    echo "  Full CIS benchmark: https://www.cisecurity.org/benchmark/apple_os"
    exit 0
fi

echo -e "${BOLD}  Section 1: Software Updates${NC}"
check "1.1" "Auto-update enabled" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled" "1"
check "1.2" "Auto-download updates" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload" "1"
check "1.3" "Install system data files" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall" "1"

echo ""
echo -e "${BOLD}  Section 2: System Protection${NC}"
check "2.1" "Gatekeeper enabled" \
    "spctl --status" "enabled"
check "2.2" "Firewall enabled" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" "enabled"
check "2.3" "Firewall stealth mode" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode" "enabled"
check "2.4" "Remote Apple Events disabled" \
    "systemsetup -getremoteappleevents" "Off"
check "2.5" "Remote Login (SSH) disabled" \
    "systemsetup -getremotelogin" "Off"
check "2.6" "Screen Sharing disabled" \
    "launchctl list com.apple.screensharing 2>&1" "Could not find"
check "2.7" "FileVault enabled" \
    "fdesetup status" "On"
check "2.8" "SIP enabled" \
    "csrutil status" "enabled"

echo ""
echo -e "${BOLD}  Section 3: Screen Lock${NC}"
check "3.1" "Screensaver password required" \
    "defaults read com.apple.screensaver askForPassword" "1"

echo ""
echo -e "${BOLD}  Section 4: Network${NC}"
check "4.1" "Bluetooth sharing disabled" \
    "defaults read /Library/Preferences/com.apple.Bluetooth PrefKeyServicesEnabled 2>&1" "0"
check "4.2" "AirDrop disabled for uncontacted" \
    "defaults read com.apple.sharingd DiscoverableMode 2>&1" "Off"

echo ""
echo -e "${BOLD}  Section 5: Access Control${NC}"
check "5.1" "Root login disabled" \
    "dscl . -read /Users/root AuthenticationAuthority 2>&1" "DisabledTags"
check "5.2" "Guest account disabled" \
    "dscl . -read /Users/Guest AuthenticationAuthority 2>&1" "DisabledTags"

echo ""
echo -e "${BOLD}  Section 6: Logging${NC}"
check "6.1" "Audit logging enabled" \
    "launchctl list com.apple.auditd" "audit"
check "6.2" "Install.log exists" \
    "ls -la /var/log/install.log" "install.log"

echo ""
echo "═══════════════════════════════════"
echo -e "  ${GREEN}PASS: $PASS${NC} | ${RED}FAIL: $FAIL${NC} | SKIP: $SKIP"
echo -e "  Score: $((PASS * 100 / (PASS + FAIL + 1)))%"
echo "═══════════════════════════════════"
