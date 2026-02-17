#!/usr/bin/env bash
# ============================================================
# Lockdown Script — The Eden's Sins Hardening
# One-shot maximum hardening for macOS
#
# WARNING: This script makes significant security changes.
# Run with --dry-run first to review changes.
#
# Usage: sudo bash lockdown.sh [--dry-run]
# ============================================================
set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
APPLIED=0

apply() {
    local desc="$1"; shift
    if $DRY_RUN; then
        echo -e "  ${YELLOW}[DRY]${NC} $desc"
        echo -e "       CMD: $*"
    else
        echo -e "  ${GREEN}[SET]${NC} $desc"
        eval "$@" 2>/dev/null || echo -e "  ${RED}[ERR]${NC} Failed: $desc"
        APPLIED=$((APPLIED + 1))
    fi
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║  THE EDEN'S SINS — macOS Lockdown          ║"
echo "║  Maximum Hardening Configuration               ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[!] Not macOS — showing lockdown commands:"
    echo ""
    echo "  # Enable Gatekeeper"
    echo "  sudo spctl --master-enable"
    echo ""
    echo "  # Enable Firewall + stealth"
    echo "  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
    echo "  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
    echo ""
    echo "  # Disable remote services"
    echo "  sudo systemsetup -setremoteappleevents off"
    echo "  sudo systemsetup -setremotelogin off"
    echo "  sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist"
    echo ""
    echo "  # Require password immediately after sleep"
    echo "  defaults write com.apple.screensaver askForPassword -int 1"
    echo "  defaults write com.apple.screensaver askForPasswordDelay -int 0"
    echo ""
    echo "  # Disable guest account"
    echo "  sudo dscl . -create /Users/Guest UserShell /usr/bin/false"
    echo ""
    echo "  # Enable audit logging"
    echo "  sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
    echo ""
    echo "  # Secure Safari"
    echo "  defaults write com.apple.Safari AutoOpenSafeDownloads -bool false"
    echo "  defaults write com.apple.Safari SendDoNotTrackHTTPHeader -bool true"
    echo ""
    echo "  # Secure sudo"
    echo "  echo 'Defaults timestamp_timeout=0' | sudo tee /etc/sudoers.d/timeout"
    exit 0
fi

if [[ $EUID -ne 0 ]] && ! $DRY_RUN; then
    echo -e "${RED}[!] This script requires root. Use: sudo bash lockdown.sh${NC}"
    echo "[*] Or use --dry-run to preview changes"
    exit 1
fi

echo -e "${YELLOW}  Mode: $( $DRY_RUN && echo 'DRY RUN (preview only)' || echo 'LIVE (applying changes!)')${NC}"
echo ""

# ─── Gatekeeper & Code Signing ───
echo -e "${CYAN}  [Gatekeeper]${NC}"
apply "Enable Gatekeeper" "spctl --master-enable"

# ─── Firewall ───
echo -e "${CYAN}  [Firewall]${NC}"
apply "Enable Application Firewall" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
apply "Enable Stealth Mode" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
apply "Enable logging" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"
apply "Block all incoming (strict)" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on"

# ─── Remote Services ───
echo -e "${CYAN}  [Remote Services]${NC}"
apply "Disable Remote Apple Events" "systemsetup -setremoteappleevents off"
apply "Disable Remote Login (SSH)" "systemsetup -setremotelogin off"

# ─── Screen Lock ───
echo -e "${CYAN}  [Screen Lock]${NC}"
apply "Require password on screensaver" \
    "defaults write com.apple.screensaver askForPassword -int 1"
apply "Password delay: 0 seconds" \
    "defaults write com.apple.screensaver askForPasswordDelay -int 0"

# ─── Privacy & Sharing ───
echo -e "${CYAN}  [Privacy]${NC}"
apply "Disable Bluetooth sharing" \
    "defaults write /Library/Preferences/com.apple.Bluetooth PrefKeyServicesEnabled -bool false"
apply "Disable AirDrop" \
    "defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"

# ─── Access Control ───
echo -e "${CYAN}  [Access Control]${NC}"
apply "Disable Guest account" \
    "dscl . -create /Users/Guest UserShell /usr/bin/false"
apply "Sudo timeout: 0 (require password each time)" \
    "echo 'Defaults timestamp_timeout=0' > /etc/sudoers.d/ct_timeout"

# ─── Safari Hardening ───
echo -e "${CYAN}  [Safari]${NC}"
apply "Disable auto-open safe downloads" \
    "defaults write com.apple.Safari AutoOpenSafeDownloads -bool false"
apply "Enable Do Not Track" \
    "defaults write com.apple.Safari SendDoNotTrackHTTPHeader -bool true"
apply "Disable Java in Safari" \
    "defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled -bool false"

# ─── Logging ───
echo -e "${CYAN}  [Logging]${NC}"
apply "Enable audit daemon" \
    "launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"

echo ""
echo "═══════════════════════════════════"
if $DRY_RUN; then
    echo -e "  ${YELLOW}DRY RUN complete — no changes made${NC}"
    echo "  Run without --dry-run to apply (with sudo)"
else
    echo -e "  ${GREEN}Applied $APPLIED hardening changes${NC}"
    echo "  Reboot recommended for full effect"
fi
echo "═══════════════════════════════════"
