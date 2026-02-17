#!/usr/bin/env bash
# ============================================================
# Keychain Enumerator — The Eden's Sins Phase 1
# MITRE ATT&CK: T1555.001 Credentials from Password Stores: Keychain
#
# Enumerates keychain metadata (service names, accounts, types)
# WITHOUT extracting actual passwords. Safe for recon phase.
#
# Usage: bash keychain_dump.sh [--full] [--output FILE]
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FULL_MODE=false
OUTPUT_FILE=""

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║  THE EDEN'S SINS — Keychain Enumerator    ║"
    echo "║  MITRE: T1555.001 Keychain                   ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [--full] [--output FILE]"
    echo "  --full    Include system keychain (may require sudo)"
    echo "  --output  Save output to file"
    exit 1
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_sec()  { echo -e "${CYAN}[*]${NC} $1"; }

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)   FULL_MODE=true; shift ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_err "Unknown option: $1"; usage ;;
    esac
done

banner

# Check platform
if [[ "$(uname)" != "Darwin" ]]; then
    log_warn "Not running on macOS. Showing documentation mode."
    echo ""
    echo "On macOS, this script would enumerate:"
    echo "  1. Login keychain metadata (service names, accounts)"
    echo "  2. System keychain entries (with --full)"
    echo "  3. Keychain search list"
    echo "  4. Certificate trust settings"
    echo ""
    echo "Key commands used:"
    echo "  security list-keychains"
    echo "  security dump-keychain login.keychain-db"
    echo "  security find-generic-password -ga 'service'"
    echo "  security find-internet-password -s 'server'"
    exit 0
fi

# ─── Keychain Search List ───
log_sec "Keychain search list:"
security list-keychains 2>/dev/null | while IFS= read -r kc; do
    kc_clean=$(echo "$kc" | tr -d '"' | xargs)
    if [[ -f "$kc_clean" ]]; then
        size=$(stat -f%z "$kc_clean" 2>/dev/null || echo "?")
        echo "    📁 $kc_clean (${size} bytes)"
    else
        echo "    📁 $kc_clean"
    fi
done
echo ""

# ─── Login Keychain Metadata ───
log_sec "Login keychain entries (metadata only, no passwords):"
LOGIN_KC="${HOME}/Library/Keychains/login.keychain-db"
if [[ -f "$LOGIN_KC" ]]; then
    # Count entries by class
    GENERIC_COUNT=0
    INET_COUNT=0
    CERT_COUNT=0
    KEY_COUNT=0

    dump_output=$(security dump-keychain "$LOGIN_KC" 2>/dev/null || true)

    if [[ -n "$dump_output" ]]; then
        GENERIC_COUNT=$(echo "$dump_output" | grep -c 'class: "genp"' || true)
        INET_COUNT=$(echo "$dump_output" | grep -c 'class: "inet"' || true)
        CERT_COUNT=$(echo "$dump_output" | grep -c 'class: "cert"' || true)
        KEY_COUNT=$(echo "$dump_output" | grep -c 'class: "keys"' || true)

        log_info "Entry summary:"
        echo "    🔑 Generic passwords : $GENERIC_COUNT"
        echo "    🌐 Internet passwords: $INET_COUNT"
        echo "    📜 Certificates      : $CERT_COUNT"
        echo "    🗝️  Keys              : $KEY_COUNT"
        echo ""

        # Extract service names (no passwords)
        log_sec "Services with stored credentials:"
        echo "$dump_output" | grep -E '0x00000007|"svce"' | \
            sed 's/.*<blob>="//;s/"$//' | \
            sort -u | head -30 | while IFS= read -r svc; do
            [[ -n "$svc" ]] && echo "    → $svc"
        done
        echo ""

        # Extract server names for internet passwords
        log_sec "Servers with stored internet passwords:"
        echo "$dump_output" | grep '"srvr"' | \
            sed 's/.*<blob>="//;s/"$//' | \
            sort -u | head -30 | while IFS= read -r srv; do
            [[ -n "$srv" ]] && echo "    → $srv"
        done
    else
        log_warn "Could not dump login keychain (locked or permissions issue)"
    fi
else
    log_err "Login keychain not found at $LOGIN_KC"
fi
echo ""

# ─── System Keychain (requires --full) ───
if $FULL_MODE; then
    log_sec "System keychain entries (may require sudo):"
    SYSTEM_KC="/Library/Keychains/System.keychain"
    if [[ -f "$SYSTEM_KC" ]]; then
        sys_dump=$(security dump-keychain "$SYSTEM_KC" 2>/dev/null || true)
        if [[ -n "$sys_dump" ]]; then
            SYS_GENERIC=$(echo "$sys_dump" | grep -c 'class: "genp"' || true)
            SYS_CERT=$(echo "$sys_dump" | grep -c 'class: "cert"' || true)
            echo "    🔑 Generic passwords : $SYS_GENERIC"
            echo "    📜 Certificates      : $SYS_CERT"
        else
            log_warn "Could not read system keychain (need sudo?)"
        fi
    else
        log_err "System keychain not found at $SYSTEM_KC"
    fi
    echo ""
fi

# ─── Trust Settings ───
log_sec "Certificate trust settings (custom overrides):"
trust_output=$(security dump-trust-settings 2>/dev/null || true)
if [[ -n "$trust_output" ]]; then
    trust_count=$(echo "$trust_output" | grep -c "Cert" || true)
    log_info "Custom trust overrides: $trust_count"
    echo "$trust_output" | head -20
else
    log_info "No custom trust settings (using system defaults)"
fi
echo ""

# ─── Risk Assessment ───
echo -e "${BOLD}─── RISK ASSESSMENT ───${NC}"
RISK_SCORE=0
TOTAL_ENTRIES=$((GENERIC_COUNT + INET_COUNT))

if [[ $TOTAL_ENTRIES -gt 100 ]]; then
    log_warn "Large keychain ($TOTAL_ENTRIES entries) — high-value target"
    RISK_SCORE=$((RISK_SCORE + 30))
elif [[ $TOTAL_ENTRIES -gt 30 ]]; then
    log_info "Medium keychain ($TOTAL_ENTRIES entries)"
    RISK_SCORE=$((RISK_SCORE + 15))
fi

# Check if keychain auto-locks
autolock=$(security show-keychain-info "$LOGIN_KC" 2>&1 || true)
if echo "$autolock" | grep -q "no-timeout"; then
    log_warn "Keychain does NOT auto-lock — persistent access possible"
    RISK_SCORE=$((RISK_SCORE + 20))
else
    log_info "Keychain has auto-lock configured"
fi

echo ""
echo -e "${BOLD}Keychain Risk Score: $RISK_SCORE/50${NC}"
echo ""
echo -e "${CYAN}[*] Detection: Monitor 'security' command usage via Unified Logging${NC}"
echo -e "${CYAN}[*] Hardening: Enable keychain auto-lock, use strong master password${NC}"

# Save output
if [[ -n "$OUTPUT_FILE" ]]; then
    exec > >(tee "$OUTPUT_FILE") 2>&1
    log_info "Output saved to $OUTPUT_FILE"
fi
