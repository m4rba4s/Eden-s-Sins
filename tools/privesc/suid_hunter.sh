#!/usr/bin/env bash
# SUID/SGID Binary Hunter — The Eden's Sins Phase 4
# MITRE ATT&CK: T1548.001 Setuid and Setgid
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }

echo -e "${CYAN}"
echo "╔═════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — SUID/SGID Hunter      ║"
echo "║  MITRE: T1548.001 Setuid/Setgid              ║"
echo "╚═════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "Documentation mode — macOS SUID/SGID hunting:"
    echo ""
    echo "  Commands:"
    echo "    find / -perm -4000 -type f 2>/dev/null  # SUID"
    echo "    find / -perm -2000 -type f 2>/dev/null  # SGID"
    echo ""
    echo "  Known exploitable SUID on macOS:"
    echo "    /usr/bin/newgrp, /usr/bin/chpass, /usr/sbin/traceroute"
    echo ""
    echo "  Detection: Monitor chmod +s, new SUID files"
    echo "  Hardening: Remove unnecessary SUID bits, use capabilities"
    exit 0
fi

# Known safe Apple SUID binaries (expected)
KNOWN_APPLE=(
    "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/login"
    "/usr/bin/passwd" "/usr/bin/newgrp" "/usr/sbin/traceroute"
    "/usr/sbin/traceroute6" "/usr/bin/at" "/usr/bin/atq"
    "/usr/bin/atrm" "/usr/bin/batch" "/usr/bin/crontab"
    "/usr/bin/quota" "/usr/sbin/postdrop" "/usr/sbin/postqueue"
)

log_info "Scanning for SUID binaries..."
suid_count=0
suspicious_count=0

while IFS= read -r binary; do
    [[ -z "$binary" ]] && continue
    suid_count=$((suid_count + 1))

    # Check if known Apple binary
    is_known=false
    for known in "${KNOWN_APPLE[@]}"; do
        if [[ "$binary" == "$known" ]]; then
            is_known=true
            break
        fi
    done

    # Check signature
    signed=false
    apple_signed=false
    if codesign -v "$binary" 2>/dev/null; then
        signed=true
        if codesign -dvv "$binary" 2>&1 | grep -q "Apple"; then
            apple_signed=true
        fi
    fi

    owner=$(stat -f "%Su:%Sg" "$binary" 2>/dev/null || echo "?:?")
    perms=$(stat -f "%Sp" "$binary" 2>/dev/null || echo "?")

    if $is_known && $apple_signed; then
        echo -e "  🟢 ${binary} (${owner}) [Apple, expected]"
    elif $signed; then
        echo -e "  🟡 ${binary} (${owner}) [Signed, non-standard]"
        suspicious_count=$((suspicious_count + 1))
    else
        echo -e "  🔴 ${binary} (${owner}) [UNSIGNED SUID!]"
        suspicious_count=$((suspicious_count + 1))
    fi
done < <(find / -perm -4000 -type f 2>/dev/null)

echo ""
log_info "Scanning for SGID binaries..."
sgid_count=0

while IFS= read -r binary; do
    [[ -z "$binary" ]] && continue
    sgid_count=$((sgid_count + 1))
    owner=$(stat -f "%Su:%Sg" "$binary" 2>/dev/null || echo "?:?")
    echo "  📁 ${binary} (${owner})"
done < <(find / -perm -2000 -type f 2>/dev/null | head -30)

echo ""
echo "═══════════════════════════════════"
echo "  SUID: $suid_count found, $suspicious_count suspicious"
echo "  SGID: $sgid_count found"
echo "═══════════════════════════════════"
echo ""
echo "  Detection: file_event on chmod with SUID bit"
echo "  Hardening: chmod u-s on non-essential SUID binaries"
echo "  osquery: SELECT * FROM suid_bin WHERE permissions LIKE '%s%'"
