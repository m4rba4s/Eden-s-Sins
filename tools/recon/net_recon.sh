#!/usr/bin/env bash
# ============================================================
# Network Recon — The Eden's Sins
# MITRE ATT&CK: T1018 Remote System Discovery, T1049 System Network
#               Connections Discovery, T1016 System Network Config
#
# Local network reconnaissance: ARP table, listening ports,
# active connections, mDNS/Bonjour discovery, routing table.
#
# Usage:
#   bash net_recon.sh [--deep] [--json] [--detect]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DEEP=false
[[ "${1:-}" == "--deep" ]] && DEEP=true
[[ "${1:-}" == "--detect" ]] && {
    echo ""
    echo "  BLUE TEAM — Network Reconnaissance Detection"
    echo "  ═════════════════════════════════════════════"
    echo ""
    echo "  Detection:"
    echo "    • Monitor arp, netstat, lsof execution"
    echo "    • Alert on dns-sd (Bonjour) enumeration"
    echo "    • Track nmap/masscan/nettop from non-admin users"
    echo "    • ESF: ES_EVENT_TYPE_NOTIFY_PROC_CHECK for network tools"
    echo "    • osquery: SELECT * FROM listening_ports"
    echo ""
    echo "  Hardening:"
    echo "    • Enable macOS Firewall stealth mode"
    echo "    • Disable unnecessary Bonjour services"
    echo "    • Segment network (VLAN isolation)"
    echo "    • Disable mDNS responder where not needed"
    echo "    • Monitor for unauthorized network scanning"
    echo ""
    exit 0
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — Network Reconnaissance     ║"
echo "║  MITRE: T1018 / T1049 / T1016                  ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Network Interfaces ───
echo -e "${BOLD}  Network Interfaces${NC}"
echo "  ─────────────────────────────────────────"

if [[ "$(uname)" == "Darwin" ]]; then
    # Active interfaces with IPs
    ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | while IFS= read -r line; do
        if echo "$line" | grep -q "^[a-z]"; then
            iface=$(echo "$line" | cut -d: -f1)
            echo -e "\n  ${GREEN}[$iface]${NC}"
        elif echo "$line" | grep -q "inet "; then
            ip=$(echo "$line" | awk '{print $2}')
            mask=$(echo "$line" | awk '{print $4}')
            echo "    IP: $ip | Mask: $mask"
        fi
    done

    # WiFi info
    echo ""
    wifi_if=$(networksetup -listallhardwareports 2>/dev/null | grep -A1 "Wi-Fi" | grep "Device" | awk '{print $2}' || echo "en0")
    echo -e "  ${BOLD}WiFi Status:${NC}"
    # Use airport utility
    airport="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if [[ -x "$airport" ]]; then
        ssid=$("$airport" -I 2>/dev/null | grep " SSID:" | awk '{print $2}')
        bssid=$("$airport" -I 2>/dev/null | grep "BSSID:" | awk '{print $2}')
        channel=$("$airport" -I 2>/dev/null | grep "channel:" | awk '{print $2}')
        security=$("$airport" -I 2>/dev/null | grep "link auth:" | awk '{print $3}')
        echo "    SSID: $ssid | BSSID: $bssid"
        echo "    Channel: $channel | Security: $security"
    else
        networksetup -getairportnetwork "$wifi_if" 2>/dev/null || true
    fi
else
    ip addr 2>/dev/null | grep -E "^[0-9]|inet " || ifconfig 2>/dev/null
fi

# ─── Default Gateway ───
echo ""
echo -e "${BOLD}  Gateway & Routing${NC}"
echo "  ─────────────────────────────────────────"
if [[ "$(uname)" == "Darwin" ]]; then
    gw=$(netstat -rn 2>/dev/null | grep "^default" | head -1 | awk '{print $2}')
    echo "  Default GW: $gw"
    
    # DNS servers
    dns=$(scutil --dns 2>/dev/null | grep "nameserver\[" | head -3 | awk '{print $3}' | tr '\n' ' ')
    echo "  DNS: $dns"
else
    ip route 2>/dev/null | grep default || route -n 2>/dev/null | head -5
fi

# ─── ARP Table ───
echo ""
echo -e "${BOLD}  ARP Table (live hosts on local network)${NC}"
echo "  ─────────────────────────────────────────"
arp_count=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Skip headers and incomplete entries
    echo "$line" | grep -q "incomplete" && continue
    echo "$line" | grep -q "^?" || echo "$line" | grep -q "^[0-9]" || continue
    
    ip=$(echo "$line" | awk '{print $1}' | tr -d '()')
    mac=$(echo "$line" | awk '{print $2}' | grep -oE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}' || echo "")
    [[ -z "$mac" ]] && mac=$(echo "$line" | awk '{print $4}')
    
    # Try to resolve hostname
    hostname=""
    if $DEEP; then
        hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | head -1 || true)
    fi
    
    echo "    $ip  →  $mac  ${hostname}"
    arp_count=$((arp_count + 1))
done < <(arp -a 2>/dev/null)
echo "  Total hosts: $arp_count"

# ─── Listening Ports ───
echo ""
echo -e "${BOLD}  Listening Ports${NC}"
echo "  ─────────────────────────────────────────"
if [[ "$(uname)" == "Darwin" ]]; then
    # Use lsof for macOS
    echo "  Proto  Port   PID    Process"
    echo "  ─────  ─────  ─────  ────────────────"
    lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        proc=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        port=$(echo "$line" | awk '{print $9}' | rev | cut -d: -f1 | rev)
        echo "    TCP   $port    $pid    $proc"
    done | sort -t' ' -k2 -n | head -30

    # UDP
    lsof -iUDP -P -n 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        proc=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        port=$(echo "$line" | awk '{print $9}' | rev | cut -d: -f1 | rev)
        echo "    UDP   $port    $pid    $proc"
    done | sort -u | head -15
else
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
fi

# ─── Active Connections ───
echo ""
echo -e "${BOLD}  Established Outbound Connections${NC}"
echo "  ─────────────────────────────────────────"
if [[ "$(uname)" == "Darwin" ]]; then
    lsof -iTCP -sTCP:ESTABLISHED -P -n 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        proc=$(echo "$line" | awk '{print $1}')
        remote=$(echo "$line" | awk '{print $9}' | grep '->' | cut -d'>' -f2 || true)
        [[ -z "$remote" ]] && continue
        echo "    $proc → $remote"
    done | sort -u | head -25
else
    ss -tnp 2>/dev/null | grep ESTAB | head -25
fi

# ─── Bonjour/mDNS Discovery ───
if $DEEP; then
    echo ""
    echo -e "${BOLD}  Bonjour/mDNS Discovery (5s scan)${NC}"
    echo "  ─────────────────────────────────────────"
    
    # Common service types to discover
    services=("_ssh._tcp" "_http._tcp" "_smb._tcp" "_afpovertcp._tcp" "_rfb._tcp" "_printer._tcp")
    
    for svc in "${services[@]}"; do
        echo -e "  ${CYAN}[$svc]${NC}"
        # dns-sd with timeout
        timeout 3 dns-sd -B "$svc" local 2>/dev/null | tail -n +5 | head -5 | while IFS= read -r line; do
            name=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ",$i; print ""}')
            echo "    → $name"
        done || true
    done
fi

# ─── Summary ───
echo ""
echo "═══════════════════════════════════════════════"
echo "  Network hosts (ARP): $arp_count"
echo "  Use --deep for DNS resolution + Bonjour scan"
echo "═══════════════════════════════════════════════"
