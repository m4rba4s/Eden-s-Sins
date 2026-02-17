#!/usr/bin/env bash
# ============================================================
# OPSEC Cleanup — The Eden's Sins
# Remove all traces after engagement. Run as LAST step.
#
# Usage:
#   bash cleanup.sh [--dry-run] [--aggressive]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DRY_RUN=false
AGGRESSIVE=false
CLEANED=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --aggressive) AGGRESSIVE=true ;;
    esac
done

nuke() {
    local desc="$1"; shift
    if $DRY_RUN; then
        echo -e "  ${YELLOW}[DRY]${NC} $desc"
        echo -e "       $*"
    else
        echo -e "  ${GREEN}[CLN]${NC} $desc"
        eval "$@" 2>/dev/null || true
        CLEANED=$((CLEANED + 1))
    fi
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — OPSEC Cleanup               ║"
echo "║  Scorched earth protocol                        ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

mode=$($DRY_RUN && echo "DRY RUN" || echo "LIVE")
echo -e "  ${BOLD}Mode: ${mode}${NC}"
if $AGGRESSIVE; then
    echo -e "  ${RED}AGGRESSIVE mode — extended cleanup${NC}"
fi
echo ""

# ─── Framework Artifacts ───
echo -e "${BOLD}  [Framework Artifacts]${NC}"
nuke "Remove screenshot captures" "rm -rf /tmp/.eden_screens"
nuke "Remove temp databases" "rm -f /tmp/ct_* /tmp/eden_* /tmp/.sysinfo"
nuke "Remove Python cache" "find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null"
nuke "Remove report outputs" "rm -f /tmp/eden_report_*.html /tmp/eden_*.json"

# ─── Shell History ───
echo -e "\n${BOLD}  [Shell History]${NC}"
if $AGGRESSIVE; then
    nuke "Clear current shell history" "history -c 2>/dev/null; history -p 2>/dev/null"

    if [[ -f "$HOME/.zsh_history" ]]; then
        nuke "Remove Eden's Sins entries from zsh_history" \
            "sed -i '' '/eden/Id; /edens/Id; /teardown/Id; /preflight/Id; /fingerprint/Id; /keychain_exfil/Id; /browser_creds/Id; /wifi_harvest/Id; /ssh_harvest/Id; /clipboard_sniff/Id; /tcc_audit/Id; /attack_chain/Id' \"$HOME/.zsh_history\""
    fi

    if [[ -f "$HOME/.bash_history" ]]; then
        nuke "Remove Eden's Sins entries from bash_history" \
            "sed -i '' '/eden/Id; /edens/Id; /teardown/Id; /preflight/Id; /fingerprint/Id' \"$HOME/.bash_history\""
    fi
else
    echo -e "  ${YELLOW}[SKIP]${NC} Shell history (use --aggressive to clean)"
fi

# ─── Persistence Artifacts ───
echo -e "\n${BOLD}  [Persistence Artifacts]${NC}"
nuke "Remove test LaunchAgents" \
    "rm -f ~/Library/LaunchAgents/com.apple.security.update.plist"
nuke "Remove test LaunchAgents (eden)" \
    "rm -f ~/Library/LaunchAgents/com.eden.*.plist"

# Unload any test agents
if [[ "$(uname)" == "Darwin" ]]; then
    for plist in ~/Library/LaunchAgents/com.eden.*.plist; do
        [[ -f "$plist" ]] && nuke "Unload $plist" "launchctl unload '$plist'"
    done
fi

# ─── Temp Files ───
echo -e "\n${BOLD}  [Temp Files]${NC}"
nuke "Clean /tmp framework files" "rm -rf /tmp/ct_race_* /tmp/eden_*"
nuke "Clean temp SQLite copies" "rm -f /tmp/tmp*.db"

# ─── Logs (aggressive only) ───
if $AGGRESSIVE; then
    echo -e "\n${BOLD}  [Log Cleanup — Aggressive]${NC}"
    nuke "Clear recent unified log entries (needs root)" \
        "sudo log erase --all 2>/dev/null || echo 'Needs root'"
    nuke "Clean ASL logs" "rm -f /var/log/asl/*.asl 2>/dev/null"
    nuke "Clean diagnostic reports" \
        "rm -f ~/Library/Logs/DiagnosticReports/*eden* 2>/dev/null"
fi

# ─── Python artifacts ───
echo -e "\n${BOLD}  [Runtime Artifacts]${NC}"
nuke "Remove .pyc files in framework" \
    "find /tmp -name '*.pyc' -path '*eden*' -delete 2>/dev/null"

# ─── Verify ───
echo ""
echo "═══════════════════════════════════════"
if $DRY_RUN; then
    echo -e "  ${YELLOW}DRY RUN — no changes made${NC}"
    echo "  Run without --dry-run to execute cleanup"
else
    echo -e "  ${GREEN}Cleaned $CLEANED items${NC}"
    echo ""
    echo "  Manual checks remaining:"
    echo "    • Verify no LaunchAgents left: ls ~/Library/LaunchAgents/"
    echo "    • Check running processes: ps aux | grep -i eden"
    echo "    • Review /tmp: ls -la /tmp/ | grep -i eden"
    echo "    • Consider: history -c && exec \$SHELL -l"
fi
echo "═══════════════════════════════════════"
