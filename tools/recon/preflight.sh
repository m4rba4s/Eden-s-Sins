#!/usr/bin/env bash
# ============================================================
# Preflight Check — The Eden's Sins
# Run BEFORE any engagement. Checks environment safety.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
WARN=0; BLOCK=0

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; WARN=$((WARN+1)); }
fail() { echo -e "  ${RED}[✗]${NC} $1"; BLOCK=$((BLOCK+1)); }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — Preflight Check            ║"
echo "║  Run this BEFORE touching anything             ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Platform ───
echo -e "${BOLD}  Platform${NC}"
if [[ "$(uname)" != "Darwin" ]]; then
    fail "NOT macOS — aborting preflight"
    exit 1
fi
ok "macOS detected"

os_ver=$(sw_vers -productVersion 2>/dev/null || echo "?")
os_build=$(sw_vers -buildVersion 2>/dev/null || echo "?")
arch=$(uname -m)
ok "Version: $os_ver ($os_build) | Arch: $arch"

if [[ "$arch" == "arm64" ]]; then
    ok "Apple Silicon — PAC/MTE active"
else
    warn "Intel x86_64 — no PAC protection"
fi

# ─── Identity ───
echo -e "\n${BOLD}  Identity${NC}"
ok "User: $(whoami) | UID: $(id -u)"
if [[ $(id -u) -eq 0 ]]; then
    warn "Running as ROOT — high forensic footprint"
else
    ok "Unprivileged — standard engagement profile"
fi

groups_list=$(groups 2>/dev/null || echo "")
if echo "$groups_list" | grep -qw "admin"; then
    ok "User is admin group member (can sudo)"
else
    warn "User NOT in admin group — limited privesc vectors"
fi

# ─── Security Controls ───
echo -e "\n${BOLD}  Security Controls${NC}"

# SIP
sip=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$sip" | grep -qi "enabled"; then
    ok "SIP: ENABLED (expected for prod target)"
else
    warn "SIP: DISABLED — unusual, may be a lab"
fi

# Gatekeeper
gk=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$gk" | grep -qi "enabled"; then
    ok "Gatekeeper: ENABLED"
else
    warn "Gatekeeper: DISABLED"
fi

# FileVault
fv=$(fdesetup status 2>/dev/null || echo "unknown")
if echo "$fv" | grep -qi "On"; then
    ok "FileVault: ON (disk encrypted)"
else
    warn "FileVault: OFF — disk not encrypted"
fi

# Firewall
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
if echo "$fw" | grep -qi "enabled"; then
    ok "Firewall: ENABLED"
else
    warn "Firewall: DISABLED"
fi

# ─── EDR / Security Tools ───
echo -e "\n${BOLD}  Threat Detection (EDR/AV)${NC}"
edr_found=false

declare -A EDR_MAP=(
    ["CrowdStrike"]="falcond|falcon-sensor"
    ["SentinelOne"]="sentineld|SentinelAgent"
    ["Carbon Black"]="cbdaemon|cbagentd"
    ["Jamf Protect"]="JamfProtect|jamf"
    ["Kandji"]="kandji"
    ["Mosyle"]="mosyle"
    ["Sophos"]="SophosScanD|SophosAntiVirus"
    ["Malwarebytes"]="Malwarebytes|RTProtectionDaemon"
    ["Norton"]="Norton|NortonSecurity"
    ["Kaspersky"]="kav|klnagent"
    ["ESET"]="esets_daemon"
    ["Objective-See"]="BlockBlock|LuLu|KnockKnock|OverSight"
    ["Santa"]="santad|Santa"
    ["osquery"]="osqueryd"
    ["XProtect Remediator"]="XProtectRemediatorMRT"
)

for name in "${!EDR_MAP[@]}"; do
    pattern="${EDR_MAP[$name]}"
    if pgrep -fi "$pattern" >/dev/null 2>&1; then
        fail "⚡ $name DETECTED — adjust OPSEC accordingly!"
        edr_found=true
    fi
done

if ! $edr_found; then
    ok "No known EDR/AV detected (check manually!)"
fi

# ─── MDM ───
echo -e "\n${BOLD}  Management (MDM)${NC}"
mdm_enrolled=false
if profiles status -type enrollment 2>/dev/null | grep -qi "enrolled"; then
    warn "MDM ENROLLED — device is managed, higher detection risk"
    mdm_enrolled=true
    profiles list 2>/dev/null | head -10
elif profiles list 2>/dev/null | grep -c "." > /dev/null 2>&1; then
    profile_count=$(profiles list 2>/dev/null | grep -c "attribute" || echo "0")
    if [[ "$profile_count" -gt 0 ]]; then
        warn "Configuration profiles found ($profile_count) — may be MDM-managed"
        mdm_enrolled=true
    fi
fi

if ! $mdm_enrolled; then
    ok "No MDM enrollment detected"
fi

# ─── Network ───
echo -e "\n${BOLD}  Network${NC}"
wifi_if=$(networksetup -listallhardwareports 2>/dev/null | grep -A1 "Wi-Fi" | grep "Device" | awk '{print $2}' || echo "en0")
wifi_ssid=$(networksetup -getairportnetwork "$wifi_if" 2>/dev/null | awk -F': ' '{print $2}' || echo "unknown")
ok "Wi-Fi SSID: $wifi_ssid"

ext_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "timeout")
ok "External IP: $ext_ip"
warn "DNS requests visible! Use --no-network tools if stealth required"

# ─── Disk Space ───
echo -e "\n${BOLD}  Resources${NC}"
disk_avail=$(df -h / 2>/dev/null | tail -1 | awk '{print $4}')
ok "Disk available: $disk_avail"

# ─── Summary ───
echo ""
echo "═══════════════════════════════════════════════"
if [[ $BLOCK -gt 0 ]]; then
    echo -e "  ${RED}BLOCKERS: $BLOCK — review before proceeding!${NC}"
fi
if [[ $WARN -gt 0 ]]; then
    echo -e "  ${YELLOW}WARNINGS: $WARN — proceed with caution${NC}"
fi
if [[ $BLOCK -eq 0 && $WARN -eq 0 ]]; then
    echo -e "  ${GREEN}ALL CLEAR — green light for engagement${NC}"
fi
echo "═══════════════════════════════════════════════"

# Recommendations
echo ""
echo -e "${BOLD}  Engagement Tips:${NC}"
if $edr_found; then
    echo "    ⚠️  EDR detected — use metadata-only modes, avoid disk writes"
    echo "    ⚠️  Pipe output to memory, don't touch /tmp"
fi
if $mdm_enrolled; then
    echo "    ⚠️  MDM — device policies may alert on tool execution"
fi
echo "    • Start with: python3 tools/recon/macos_fingerprint.py"
echo "    • Use --dry-run on all persistence tools"
echo "    • Run cleanup.sh when done"
