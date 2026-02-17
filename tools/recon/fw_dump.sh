#!/usr/bin/env bash
# ============================================================
# Firewall Rule Dump — The Eden's Sins
# MITRE ATT&CK: T1518 Software Discovery, T1562.004 Disable Firewall
#
# Dumps macOS firewall configuration:
# - Application Firewall (socketfilterfw) state + rules
# - PF (packet filter) rules if configured
# - Network service port exposure
# - Identifies exfiltration-friendly gaps
#
# Usage:
#   bash fw_dump.sh [--deep] [--detect]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DEEP=false
[[ "${1:-}" == "--deep" ]] && DEEP=true
[[ "${1:-}" == "--detect" ]] && {
    echo ""
    echo "  BLUE TEAM — Firewall Bypass Detection"
    echo "  ══════════════════════════════════════"
    echo ""
    echo "  Detection:"
    echo "    • Monitor socketfilterfw state changes"
    echo "    • Alert on pfctl rule modifications"
    echo "    • Track /etc/pf.conf changes"
    echo "    • ESF: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN for network stack"
    echo "    • osquery: SELECT * FROM alf_services; SELECT * FROM alf_exceptions"
    echo ""
    echo "  Hardening:"
    echo "    • Enable firewall + stealth mode"
    echo "    • Block all incoming by default"
    echo "    • Only allow signed apps"
    echo "    • Use pfctl for advanced rules"
    echo "    • MDM: enforce firewall state via profile"
    echo ""
    exit 0
}

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Not macOS — documentation mode"
    echo ""
    echo "  macOS has two firewall layers:"
    echo "    1. Application Firewall (ALF) — socketfilterfw"
    echo "       Controls per-app incoming connections"
    echo "    2. PF (Packet Filter) — pfctl"
    echo "       BSD-level packet filtering (like iptables)"
    echo ""
    echo "  Commands:"
    echo "    socketfilterfw --getglobalstate"
    echo "    socketfilterfw --listapps"
    echo "    pfctl -sr  # show rules"
    echo "    pfctl -sa  # show all"
    exit 0
fi

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — Firewall Analysis           ║"
echo "║  MITRE: T1518 / T1562.004                      ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

SFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

# ─── Application Firewall (ALF) ───
echo -e "${BOLD}  Application Firewall (ALF)${NC}"
echo "  ────────────────────────────────────"

# Global state
state=$($SFW --getglobalstate 2>/dev/null || echo "unknown")
if echo "$state" | grep -qi "enabled"; then
    echo -e "  State: ${GREEN}ENABLED${NC}"
else
    echo -e "  State: ${RED}DISABLED ← exfil friendly!${NC}"
fi

# Stealth mode
stealth=$($SFW --getstealthmode 2>/dev/null || echo "unknown")
if echo "$stealth" | grep -qi "enabled"; then
    echo -e "  Stealth: ${GREEN}ENABLED${NC} (ignores pings/probes)"
else
    echo -e "  Stealth: ${YELLOW}DISABLED${NC}"
fi

# Block all mode
blockall=$($SFW --getblockall 2>/dev/null || echo "unknown")
echo "  Block all incoming: $blockall"

# Logging
logging=$($SFW --getloggingmode 2>/dev/null || echo "unknown")
echo "  Logging: $logging"

# Signed apps auto-allow
echo ""
echo -e "${BOLD}  App Rules (socketfilterfw)${NC}"
echo "  ────────────────────────────────────"

$SFW --listapps 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -q "BLOCK"; then
        echo -e "    ${RED}[BLOCK]${NC} $line"
    elif echo "$line" | grep -q "ALLOW"; then
        echo -e "    ${GREEN}[ALLOW]${NC} $line"
    fi
done | head -30

echo ""

# ─── PF (Packet Filter) ───
echo -e "${BOLD}  PF Packet Filter${NC}"
echo "  ────────────────────────────────────"

# Check if PF is enabled
pf_status=$(pfctl -s info 2>/dev/null | head -1 || echo "unknown/no access")
echo "  PF Status: $pf_status"

# Show rules (may need root)
echo ""
echo "  Active PF rules:"
pfctl -sr 2>/dev/null | head -20 | while IFS= read -r rule; do
    echo "    $rule"
done

if [[ $? -ne 0 ]]; then
    echo "    (Need root: sudo pfctl -sr)"
fi

# PF config file
echo ""
if [[ -f /etc/pf.conf ]]; then
    echo "  /etc/pf.conf exists:"
    grep -v "^#" /etc/pf.conf 2>/dev/null | grep -v "^$" | head -15 | while IFS= read -r line; do
        echo "    $line"
    done
else
    echo "  /etc/pf.conf: not found (no custom PF rules)"
fi

# ─── Exfiltration Analysis ───
echo ""
echo -e "${BOLD}  Exfiltration Channel Analysis${NC}"
echo "  ────────────────────────────────────"

# Check common exfil ports
common_ports=("80:HTTP" "443:HTTPS" "53:DNS" "8080:Alt-HTTP" "8443:Alt-HTTPS" "22:SSH")
echo "  Testing outbound connectivity to common exfil ports:"

for port_info in "${common_ports[@]}"; do
    port="${port_info%%:*}"
    name="${port_info##*:}"

    # Quick TCP check to Google DNS or localhost
    if $DEEP; then
        if nc -z -w2 8.8.8.8 "$port" 2>/dev/null; then
            echo -e "    ${GREEN}[OPEN]${NC} Port $port ($name) — exfil possible"
        else
            echo -e "    ${RED}[BLOCKED]${NC} Port $port ($name)"
        fi
    else
        echo "    Port $port ($name) — use --deep to test connectivity"
    fi
done

# DNS exfil check
echo ""
echo "  DNS exfiltration:"
if $DEEP; then
    dns_test=$(dig +short TXT test.openresolver.com 2>/dev/null || echo "failed")
    if [[ "$dns_test" != "failed" && -n "$dns_test" ]]; then
        echo -e "    ${YELLOW}[POSSIBLE]${NC} DNS resolution works — DNS tunneling viable"
    else
        echo -e "    ${GREEN}[LIMITED]${NC} DNS resolution restricted"
    fi
else
    echo "    Use --deep to test DNS exfiltration viability"
fi

# ─── Summary ───
echo ""
echo "═══════════════════════════════════════════════"
echo "  ALF: $state | Stealth: $stealth"
echo "  PF: $pf_status"

# Risk assessment
risk=0
echo "$state" | grep -qi "disabled" && risk=$((risk + 30))
echo "$stealth" | grep -qi "disabled" && risk=$((risk + 10))
echo "$blockall" | grep -qi "disabled" && risk=$((risk + 15))

if [[ $risk -gt 30 ]]; then
    echo -e "  Firewall Risk: ${RED}HIGH ($risk/100)${NC}"
elif [[ $risk -gt 10 ]]; then
    echo -e "  Firewall Risk: ${YELLOW}MEDIUM ($risk/100)${NC}"
else
    echo -e "  Firewall Risk: ${GREEN}LOW ($risk/100)${NC}"
fi
echo "═══════════════════════════════════════════════"
