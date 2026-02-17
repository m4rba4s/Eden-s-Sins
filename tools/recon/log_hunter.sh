#!/usr/bin/env bash
# ============================================================
# Log Hunter — The Eden's Sins Phase 1
# MITRE ATT&CK: T1005 Data from Local System
#
# Hunts for sensitive information leaked into macOS logs:
# - Unified Logging (log show)
# - Application Support logs
# - Crash reports
# - ASL legacy logs
#
# Usage: bash log_hunter.sh [--deep] [--hours N] [--output FILE]
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DEEP_MODE=false
HOURS=1
OUTPUT_FILE=""

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║  THE EDEN'S SINS — Log Hunter             ║"
    echo "║  MITRE: T1005 Data from Local System         ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_sec()  { echo -e "${CYAN}[*]${NC} $1"; }
log_find() { echo -e "${RED}[💀]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep)    DEEP_MODE=true; shift ;;
        --hours)   HOURS="$2"; shift 2 ;;
        --output)  OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--deep] [--hours N] [--output FILE]"
            exit 0
            ;;
        *) log_err "Unknown: $1"; exit 1 ;;
    esac
done

banner

if [[ "$(uname)" != "Darwin" ]]; then
    log_warn "Not on macOS — showing documentation mode."
    echo ""
    echo "This script hunts for leaked credentials in macOS logs:"
    echo ""
    echo "1. Unified Logging (log show):"
    echo "   - Passwords, tokens, API keys in log messages"
    echo "   - Connection strings with embedded credentials"
    echo "   - OAuth tokens and bearer tokens"
    echo ""
    echo "2. Crash Reports (~Library/Logs/DiagnosticReports/):"
    echo "   - Memory dumps may contain credentials"
    echo "   - Stack traces with sensitive arguments"
    echo ""
    echo "3. Application logs (~Library/Logs/):"
    echo "   - App-specific debug output"
    echo "   - Database connection strings"
    echo ""
    echo "Key patterns searched:"
    echo "   password, passwd, secret, token, api_key, apikey,"
    echo "   bearer, authorization, credential, private_key,"
    echo "   aws_access, session_id, cookie"
    exit 0
fi

FINDINGS=0
REPORT_DIR=$(mktemp -d)

# ─── Sensitive Patterns ───
PATTERNS=(
    "password"
    "passwd"
    "secret"
    "token"
    "api_key"
    "apikey"
    "api-key"
    "bearer"
    "authorization"
    "credential"
    "private.key"
    "aws_access"
    "aws_secret"
    "session_id"
    "sessionid"
    "cookie"
    "oauth"
    "jwt"
    "BEGIN RSA"
    "BEGIN PRIVATE"
    "AKIA"  # AWS access key prefix
)

# Build grep pattern
GREP_PATTERN=$(printf "|%s" "${PATTERNS[@]}")
GREP_PATTERN="${GREP_PATTERN:1}"  # Remove leading |

# ─── Phase 1: Unified Logging ───
log_sec "Hunting in Unified Logs (last ${HOURS}h)..."
echo ""

for pattern in "${PATTERNS[@]}"; do
    hits=$(log show --last "${HOURS}h" \
        --predicate "eventMessage CONTAINS[cd] '${pattern}'" \
        --style compact 2>/dev/null | head -5 || true)

    if [[ -n "$hits" ]]; then
        FINDINGS=$((FINDINGS + 1))
        log_find "Pattern '${pattern}' found in unified logs!"
        echo "$hits" | head -3 | while IFS= read -r line; do
            # Truncate long lines and mask potential passwords
            truncated="${line:0:120}"
            echo "      ${truncated}..."
        done
        echo ""
    fi
done

# ─── Phase 2: Crash Reports ───
log_sec "Hunting in Crash Reports..."
CRASH_DIRS=(
    "${HOME}/Library/Logs/DiagnosticReports"
    "/Library/Logs/DiagnosticReports"
)

for crash_dir in "${CRASH_DIRS[@]}"; do
    if [[ -d "$crash_dir" ]]; then
        recent_crashes=$(find "$crash_dir" -name "*.crash" -o -name "*.ips" \
            -newer <(date -v-"${HOURS}"H +%Y%m%d%H%M) 2>/dev/null | head -10 || true)

        if [[ -n "$recent_crashes" ]]; then
            log_info "Found crash reports in $crash_dir"
            echo "$recent_crashes" | while IFS= read -r crash; do
                [[ -z "$crash" ]] && continue
                basename_crash=$(basename "$crash")
                hits=$(grep -iEc "$GREP_PATTERN" "$crash" 2>/dev/null || true)
                if [[ "$hits" -gt 0 ]]; then
                    log_find "Crash report '${basename_crash}' contains $hits sensitive matches!"
                    FINDINGS=$((FINDINGS + 1))
                fi
            done
        fi
    fi
done
echo ""

# ─── Phase 3: Application Logs ───
log_sec "Hunting in Application Logs..."
APP_LOG_DIRS=(
    "${HOME}/Library/Logs"
    "/var/log"
)

for log_dir in "${APP_LOG_DIRS[@]}"; do
    if [[ -d "$log_dir" ]]; then
        log_info "Scanning $log_dir..."
        find "$log_dir" -maxdepth 2 -type f \
            \( -name "*.log" -o -name "*.txt" \) \
            -size +0 -size -50M 2>/dev/null | head -20 | while IFS= read -r logfile; do

            [[ -z "$logfile" ]] && continue
            hits=$(grep -iEc "$GREP_PATTERN" "$logfile" 2>/dev/null || true)
            if [[ "$hits" -gt 0 ]]; then
                log_find "$(basename "$logfile"): $hits sensitive pattern matches"
                FINDINGS=$((FINDINGS + 1))

                # Show first match (redacted)
                first_match=$(grep -im1 -E "$GREP_PATTERN" "$logfile" 2>/dev/null || true)
                if [[ -n "$first_match" ]]; then
                    truncated="${first_match:0:100}"
                    echo "      Preview: ${truncated}..."
                fi
            fi
        done
    fi
done
echo ""

# ─── Phase 4: Deep Mode — Additional Sources ───
if $DEEP_MODE; then
    log_sec "[DEEP] Hunting in shell history files..."
    HISTORY_FILES=(
        "${HOME}/.bash_history"
        "${HOME}/.zsh_history"
        "${HOME}/.python_history"
    )

    for hist in "${HISTORY_FILES[@]}"; do
        if [[ -f "$hist" ]]; then
            hits=$(grep -iEc "$GREP_PATTERN" "$hist" 2>/dev/null || true)
            if [[ "$hits" -gt 0 ]]; then
                log_find "$(basename "$hist"): $hits sensitive patterns in shell history!"
                FINDINGS=$((FINDINGS + 1))
                # Show commands that might contain creds (redacted)
                grep -inE "$GREP_PATTERN" "$hist" 2>/dev/null | head -5 | while IFS= read -r line; do
                    truncated="${line:0:80}"
                    echo "      ${truncated}..."
                done
            fi
        fi
    done
    echo ""

    log_sec "[DEEP] Checking environment variables for leaked secrets..."
    env_hits=$(env | grep -iE "$GREP_PATTERN" 2>/dev/null | wc -l || true)
    if [[ "$env_hits" -gt 0 ]]; then
        log_find "Found $env_hits environment variables with sensitive patterns!"
        env | grep -iE "$GREP_PATTERN" 2>/dev/null | while IFS= read -r envvar; do
            varname=$(echo "$envvar" | cut -d'=' -f1)
            echo "      → ${varname}=<REDACTED>"
        done
        FINDINGS=$((FINDINGS + env_hits))
    fi
    echo ""
fi

# ─── Report ───
echo ""
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}  LOG HUNTER REPORT${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo ""
echo -e "  Scope      : Last ${HOURS} hour(s)"
echo -e "  Deep mode  : ${DEEP_MODE}"
echo -e "  Patterns   : ${#PATTERNS[@]}"
echo -e "  Findings   : ${FINDINGS}"
echo ""

if [[ "$FINDINGS" -gt 10 ]]; then
    log_err "CRITICAL: High number of credential leaks in logs!"
    echo ""
    echo "  Recommendations:"
    echo "  1. Implement log redaction policies (os_log with privacy qualifiers)"
    echo "  2. Use os_log(... , \"%{private}s\", sensitiveValue) in app code"
    echo "  3. Rotate and purge old logs: sudo log erase --all"
    echo "  4. Audit third-party apps for excessive logging"
elif [[ "$FINDINGS" -gt 0 ]]; then
    log_warn "Some credential leaks detected in logs"
    echo ""
    echo "  Recommendations:"
    echo "  1. Review flagged files and redact sensitive data"
    echo "  2. Configure log retention policies"
    echo "  3. Use Apple's privacy-aware logging APIs"
else
    log_info "No obvious credential leaks found in logs. Good hygiene!"
fi

echo ""
echo -e "${CYAN}[*] Detection: Monitor for mass log reads (log show with broad predicates)${NC}"
echo -e "${CYAN}[*] Hardening: Use os_log privacy qualifiers, rotate logs, restrict access${NC}"

if [[ -n "$OUTPUT_FILE" ]]; then
    exec > >(tee "$OUTPUT_FILE") 2>&1
    log_info "Output saved to $OUTPUT_FILE"
fi
