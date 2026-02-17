#!/usr/bin/env bash
# ============================================================
# Gatekeeper & Quarantine Analyzer — The Eden's Sins Phase 2
# MITRE ATT&CK: T1553.001 Subvert Trust Controls: Gatekeeper Bypass
#
# Analyzes Gatekeeper configuration and quarantine attributes:
# - Gatekeeper policy status
# - Quarantine xattr analysis
# - Code signing validation
# - Known bypass technique checks
#
# Usage: bash gatekeeper_check.sh [--scan PATH] [--deep]
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCAN_PATH=""
DEEP_MODE=false

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  THE EDEN'S SINS — Gatekeeper Analyzer        ║"
    echo "║  MITRE: T1553.001 Gatekeeper Bypass              ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_sec()  { echo -e "${CYAN}[*]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan) SCAN_PATH="$2"; shift 2 ;;
        --deep) DEEP_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--scan PATH] [--deep]"
            exit 0
            ;;
        *) log_err "Unknown: $1"; exit 1 ;;
    esac
done

banner

if [[ "$(uname)" != "Darwin" ]]; then
    log_warn "Not on macOS — documentation mode."
    echo ""
    echo "Gatekeeper Security Architecture:"
    echo "══════════════════════════════════"
    echo ""
    echo "  Gatekeeper = Apple's code trust enforcement system"
    echo ""
    echo "  Components:"
    echo "    1. spctl — Security Policy Control CLI"
    echo "    2. com.apple.quarantine xattr — marks downloaded files"
    echo "    3. Notarization — Apple's malware check service"
    echo "    4. XProtect — signature-based malware detection"
    echo ""
    echo "  Enforcement Flow:"
    echo "    Download → quarantine xattr set → first launch →"
    echo "    Gatekeeper checks signature → Notarization check →"
    echo "    XProtect scan → allow/block"
    echo ""
    echo "  Known Bypass Techniques:"
    echo "    1. Remove quarantine xattr: xattr -d com.apple.quarantine FILE"
    echo "    2. Copy via command line (no quarantine xattr set)"
    echo "    3. Archive extraction tools that strip quarantine"
    echo "    4. AppleScript execution (no Gatekeeper check)"
    echo "    5. Python/Ruby/etc scripts (interpreted, not checked)"
    echo "    6. curl/wget downloads (no quarantine by default)"
    echo ""
    echo "  Detection:"
    echo "    • Monitor xattr -d com.apple.quarantine commands"
    echo "    • Track unsigned binary execution"
    echo "    • Alert on spctl --master-disable"
    echo "    • Monitor GatekeeperXPC service logs"
    echo ""
    echo "  Hardening:"
    echo "    • Keep Gatekeeper enabled (spctl --master-enable)"
    echo "    • Enforce notarization via MDM"
    echo "    • Block unsigned code execution via Santa/JAMF"
    echo "    • Monitor quarantine xattr removal"
    exit 0
fi

# ─── Gatekeeper Status ───
log_sec "Gatekeeper status:"
gk_status=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$gk_status" | grep -qi "enabled"; then
    log_info "Gatekeeper: ENABLED ✓"
else
    log_err "Gatekeeper: DISABLED — unsigned code can run freely!"
fi

# Assessment level
gk_assess=$(spctl --assess --type execute /usr/bin/true 2>&1 || true)
log_info "Assessment: $gk_assess"
echo ""

# ─── Gatekeeper Policies ───
log_sec "Gatekeeper policies (spctl --list):"
spctl --list 2>/dev/null | head -20 || log_warn "Cannot list policies"
echo ""

# ─── Notarization Status ───
log_sec "Notarization enforcement:"
# Check if notarization is required
notar_status=$(defaults read /Library/Preferences/com.apple.security.GKAutoUpdate 2>/dev/null || echo "default")
log_info "GKAutoUpdate: $notar_status"

# ─── XProtect Version ───
log_sec "XProtect version:"
xp_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
if [[ -f "$xp_plist" ]]; then
    xp_version=$(defaults read "$xp_plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
    log_info "XProtect version: $xp_version"
else
    log_warn "XProtect bundle not found"
fi

# MRT (Malware Removal Tool)
mrt_path="/Library/Apple/System/Library/CoreServices/MRT.app"
if [[ -d "$mrt_path" ]]; then
    mrt_version=$(defaults read "${mrt_path}/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
    log_info "MRT version: $mrt_version"
fi
echo ""

# ─── Quarantine Analysis ───
if [[ -n "$SCAN_PATH" ]]; then
    log_sec "Scanning quarantine attributes in: $SCAN_PATH"
    echo ""

    quarantined=0
    unquarantined=0
    total=0

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        total=$((total + 1))

        q_attr=$(xattr -p com.apple.quarantine "$file" 2>/dev/null || true)
        if [[ -n "$q_attr" ]]; then
            quarantined=$((quarantined + 1))
            if $DEEP_MODE; then
                # Parse quarantine value: flags;timestamp;agent;uuid
                IFS=';' read -r q_flags q_ts q_agent q_uuid <<< "$q_attr"
                echo "  📦 $(basename "$file")"
                echo "     Flags: $q_flags | Agent: $q_agent"
            fi
        else
            unquarantined=$((unquarantined + 1))
            # Check if it should have quarantine
            if file "$file" 2>/dev/null | grep -qE "Mach-O|executable|script"; then
                log_warn "Executable without quarantine: $(basename "$file")"
            fi
        fi
    done < <(find "$SCAN_PATH" -maxdepth 3 -type f 2>/dev/null | head -200)

    echo ""
    log_info "Scan results: $total files, $quarantined quarantined, $unquarantined unquarantined"

    if [[ $unquarantined -gt 0 ]]; then
        log_warn "$unquarantined files lack quarantine xattr"
        log_warn "These files bypassed Gatekeeper (downloaded via CLI, extracted, or stripped)"
    fi
    echo ""
fi

# ─── Bypass Technique Checks ───
log_sec "Known bypass vector checks:"
echo ""

# Check 1: curl/wget in history (downloads without quarantine)
for hist_file in "$HOME/.zsh_history" "$HOME/.bash_history"; do
    if [[ -f "$hist_file" ]]; then
        dl_cmds=$(grep -cE 'curl.*-[oO]|wget' "$hist_file" 2>/dev/null || true)
        if [[ "$dl_cmds" -gt 0 ]]; then
            log_warn "Found $dl_cmds curl/wget download commands in history"
            log_warn "CLI downloads DON'T set quarantine xattr!"
        fi
    fi
done

# Check 2: Python/Ruby scripts in common locations
script_count=$(find /usr/local/bin "$HOME"/bin "$HOME"/.local/bin \
    -name "*.py" -o -name "*.rb" -o -name "*.sh" 2>/dev/null | wc -l || true)
if [[ "$script_count" -gt 0 ]]; then
    log_info "$script_count scripts found — interpreters bypass Gatekeeper"
fi

# Check 3: xattr removal in history
for hist_file in "$HOME/.zsh_history" "$HOME/.bash_history"; do
    if [[ -f "$hist_file" ]]; then
        xattr_rm=$(grep -c 'xattr.*-d.*quarantine' "$hist_file" 2>/dev/null || true)
        if [[ "$xattr_rm" -gt 0 ]]; then
            log_err "Found $xattr_rm quarantine xattr removal commands in history!"
        fi
    fi
done

# Check 4: Unsigned binaries in common paths
log_sec "Checking for unsigned binaries in /usr/local/bin..."
unsigned_count=0
if [[ -d "/usr/local/bin" ]]; then
    while IFS= read -r bin; do
        [[ -z "$bin" ]] && continue
        if ! codesign -v "$bin" 2>/dev/null; then
            unsigned_count=$((unsigned_count + 1))
            if $DEEP_MODE; then
                log_warn "Unsigned: $(basename "$bin")"
            fi
        fi
    done < <(find /usr/local/bin -maxdepth 1 -type f -perm +111 2>/dev/null | head -50)
fi
log_info "Unsigned binaries in /usr/local/bin: $unsigned_count"

echo ""

# ─── Blue Team Summary ───
echo -e "${BOLD}═══ DETECTION & HARDENING ═══${NC}"
echo ""
echo "  Detection:"
echo "    • Monitor: log stream --predicate 'subsystem == \"com.apple.security.gatekeeper\"'"
echo "    • Alert: xattr -d com.apple.quarantine in process commands"
echo "    • Track: spctl --assess failures in logs"
echo "    • osquery: SELECT * FROM xattr_where_key_like 'quarantine'"
echo ""
echo "  Hardening:"
echo "    • spctl --master-enable  (force Gatekeeper on)"
echo "    • MDM: Restrict app sources to App Store + identified developers"
echo "    • Santa: allowlist-based execution control"
echo "    • Monitor CLI download tools (curl, wget) for sensitivity"
echo "    • Enforce notarization for all internal tools"
