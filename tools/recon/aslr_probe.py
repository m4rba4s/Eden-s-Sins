#!/usr/bin/env python3
"""
ASLR Probe — The Eden's Sins Phase 1
MITRE ATT&CK: T1057 Process Discovery

Demonstrates ASLR information leak concepts on macOS:
1. NSDictionary serialization leak (Google Project Zero technique)
2. Shared cache slide detection
3. Dyld info extraction

This is a CONCEPTUAL DEMONSTRATOR showing how ASLR can be probed.
It does NOT contain a working exploit — it documents the technique
and shows the defensive perspective.

Usage:
    python3 aslr_probe.py [--check-only] [--verbose]

References:
    - Google Project Zero: "A Very Deep Dive into iOS Exploit Chains"
    - CVE-2020-27930: Memory corruption in FontParser
    - Apple ASLR implementation in XNU kernel

Author: The Eden's Sins / Purple Team
"""

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import struct
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass
class ASLRReport:
    """ASLR analysis report."""
    platform: str = ""
    architecture: str = ""
    aslr_enabled: bool = True
    pie_enabled: bool = True
    shared_cache_slide: str = "unknown"
    dyld_base: str = "unknown"
    kernel_aslr: str = "unknown"
    findings: list = field(default_factory=list)
    risk_level: str = "LOW"
    recommendations: list = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Execute command safely."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def check_platform(report: ASLRReport) -> bool:
    """Verify we're on macOS."""
    report.platform = platform.system()
    report.architecture = platform.machine()

    if report.platform != "Darwin":
        print("[!] Not on macOS. Showing conceptual documentation.\n")
        return False
    return True


def check_pie_binary(binary_path: str) -> bool:
    """Check if a binary is compiled as PIE (Position Independent Executable)."""
    rc, out, _ = _run(["otool", "-hv", binary_path])
    if rc == 0:
        return "PIE" in out
    return True  # Assume PIE if can't check


def check_aslr_status(report: ASLRReport) -> None:
    """Check system ASLR configuration."""
    # On macOS, ASLR is always on unless SIP is disabled and
    # boot-args contain specific flags
    rc, out, _ = _run(["sysctl", "kern.aslr"])
    if rc == 0:
        report.findings.append(f"kern.aslr: {out}")
        if "0" in out:
            report.aslr_enabled = False
            report.risk_level = "CRITICAL"
            report.findings.append("⚠️ ASLR appears to be DISABLED!")

    # Check if common system binaries are PIE
    test_binaries = ["/usr/bin/ssh", "/usr/bin/sudo", "/bin/ls"]
    non_pie = []
    for binary in test_binaries:
        if os.path.exists(binary) and not check_pie_binary(binary):
            non_pie.append(binary)

    if non_pie:
        report.findings.append(
            f"Non-PIE binaries found: {', '.join(non_pie)}"
        )
        report.risk_level = "MEDIUM"
    else:
        report.findings.append("All tested system binaries are PIE ✓")


def probe_shared_cache(report: ASLRReport) -> None:
    """Examine dyld shared cache slide."""
    # dyld_shared_cache location
    cache_paths = [
        "/System/Library/dyld/dyld_shared_cache_arm64e",
        "/System/Library/dyld/dyld_shared_cache_x86_64h",
        "/System/Library/dyld/dyld_shared_cache_x86_64",
    ]

    for cache_path in cache_paths:
        if os.path.exists(cache_path):
            report.findings.append(
                f"Shared cache found: {cache_path}"
            )
            # Get cache info via dyld
            rc, out, _ = _run([
                "dyld_info", "-platform", cache_path
            ])
            if rc == 0:
                report.shared_cache_slide = "Present (slide applied)"
            break

    # Use dyld environment to check slide
    rc, out, _ = _run(["dyld_info", "-fixups", "/usr/bin/true"])
    if rc == 0 and out:
        report.findings.append(
            "dyld_info available — can analyze library load addresses"
        )


def analyze_dyld_info(report: ASLRReport) -> None:
    """Extract dyld information that could leak ASLR."""
    # Environment variables that affect ASLR
    dangerous_envvars = {
        "DYLD_INSERT_LIBRARIES": "Allows library injection",
        "DYLD_LIBRARY_PATH": "Can redirect library loading",
        "DYLD_PRINT_SEGMENTS": "Leaks segment addresses",
        "DYLD_PRINT_BINDINGS": "Leaks symbol binding addresses",
        "DYLD_PRINT_APIS": "Leaks API call addresses",
        "DYLD_PRINT_STATISTICS": "Leaks timing info (side-channel)",
    }

    active_leaks = []
    for envvar, risk in dangerous_envvars.items():
        if os.environ.get(envvar):
            active_leaks.append(f"{envvar}: {risk}")

    if active_leaks:
        report.risk_level = "HIGH"
        report.findings.append(
            f"Active DYLD leak variables: {len(active_leaks)}"
        )
        for leak in active_leaks:
            report.findings.append(f"  ⚠️ {leak}")
    else:
        report.findings.append(
            "No dangerous DYLD environment variables set ✓"
        )


def document_nsdictionary_leak(report: ASLRReport) -> None:
    """
    Document the NSDictionary serialization ASLR leak technique.

    This is the Google Project Zero technique where:
    1. A crafted NSDictionary with hash collisions is sent to a target
    2. The target re-serializes it (e.g., via NSKeyedArchiver)
    3. The order of keys changes based on internal pointer values
    4. The attacker can determine NSNull singleton address from the ordering
    5. This leaks the shared cache base address, defeating ASLR

    We document this WITHOUT implementing the actual exploit.
    """
    technique = {
        "name": "NSDictionary Serialization ASLR Leak",
        "source": "Google Project Zero",
        "mechanism": (
            "NSDictionary uses pointer-derived hash values internally. "
            "When a dictionary is serialized → sent to victim → deserialized "
            "→ re-serialized, the key ordering changes based on internal "
            "pointer addresses (e.g., NSNull singleton). "
            "By crafting dictionaries with specific hash collision patterns, "
            "an attacker can determine memory layout from the response."
        ),
        "prerequisites": [
            "Target must deserialize attacker-controlled NSDictionary",
            "Target must re-serialize and return the dictionary",
            "Shared cache must contain the probed object (e.g., NSNull)",
        ],
        "affected_versions": "macOS < 11.0 (partially mitigated after)",
        "defense": [
            "Don't re-serialize untrusted data without validation",
            "Use NSSecureCoding with strict type checking",
            "Randomize internal hash seeds (Apple mitigation)",
            "Validate serialization round-trip consistency",
        ],
        "detection": [
            "Monitor for unusual NSKeyedArchiver/Unarchiver activity",
            "Detect large/malformed plists in IPC channels",
            "Profile normal serialization patterns to detect anomalies",
        ],
    }

    report.findings.append(
        "Documented NSDictionary ASLR leak technique (P0 style)"
    )
    report.recommendations.extend(technique["defense"])

    return technique


def document_pointer_auth_interaction(report: ASLRReport) -> None:
    """Document how PAC interacts with ASLR on Apple Silicon."""
    if report.architecture == "arm64":
        report.findings.append(
            "Apple Silicon detected — PAC (Pointer Authentication) active"
        )
        report.findings.append(
            "PAC adds cryptographic signatures to pointers, "
            "making ASLR bypass harder even with info leak"
        )
        report.findings.append(
            "PAC contexts: IA (instruction), DA (data), IB, DB, GA"
        )
        report.recommendations.append(
            "Ensure Hardened Runtime is enabled for all binaries "
            "(enforces PAC usage)"
        )
    else:
        report.findings.append(
            "Intel architecture — no PAC protection. "
            "ASLR bypass is sufficient for code reuse attacks."
        )
        report.risk_level = "MEDIUM"


def generate_report(report: ASLRReport, verbose: bool = False) -> str:
    """Generate final report."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — ASLR Analysis Report",
        "=" * 60,
        "",
        f"  Platform      : {report.platform}",
        f"  Architecture  : {report.architecture}",
        f"  ASLR Status   : {'✅ Enabled' if report.aslr_enabled else '❌ Disabled'}",
        f"  PIE Binaries  : {'✅ Yes' if report.pie_enabled else '❌ No'}",
        f"  Risk Level    : {report.risk_level}",
        "",
        "─" * 60,
        "  FINDINGS",
        "─" * 60,
    ]

    for finding in report.findings:
        lines.append(f"  • {finding}")

    lines.extend([
        "",
        "─" * 60,
        "  DEFENSE RECOMMENDATIONS",
        "─" * 60,
    ])

    default_recommendations = [
        "Keep SIP enabled at all times",
        "Ensure all custom binaries are compiled as PIE",
        "Use Hardened Runtime for all production binaries",
        "Monitor for DYLD_PRINT_* environment variables",
        "Implement NSSecureCoding for all serialization",
        "On Apple Silicon: verify PAC is not bypassed via entitlements",
    ]
    all_recs = list(set(report.recommendations + default_recommendations))
    for i, rec in enumerate(all_recs, 1):
        lines.append(f"  {i}. {rec}")

    lines.extend([
        "",
        "─" * 60,
        "  DETECTION GUIDANCE",
        "─" * 60,
        "  • Monitor: log stream --predicate 'process == \"dyld\"'",
        "  • Detect: unusual DYLD_* env vars in process monitoring",
        "  • Alert: non-PIE binaries in /usr/local/bin or /Applications",
        "  • Hunt: large serialized plists in XPC traffic",
        "",
        "=" * 60,
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASLR Probe — The Eden's Sins"
    )
    parser.add_argument(
        "--check-only", action="store_true",
        help="Only check ASLR status, don't probe",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show detailed technique documentation",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON",
    )
    args = parser.parse_args()

    report = ASLRReport()
    is_macos = check_platform(report)

    if is_macos:
        check_aslr_status(report)
        if not args.check_only:
            probe_shared_cache(report)
            analyze_dyld_info(report)
            document_pointer_auth_interaction(report)

    # Always include technique documentation
    technique = document_nsdictionary_leak(report)

    if args.json:
        data = asdict(report)
        if args.verbose:
            data["nsdictionary_technique"] = technique
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(generate_report(report, args.verbose))

        if args.verbose:
            print("\n" + "=" * 60)
            print("  NSDictionary ASLR Leak — Technical Deep Dive")
            print("=" * 60)
            for key, val in technique.items():
                if isinstance(val, list):
                    print(f"\n  {key}:")
                    for item in val:
                        print(f"    • {item}")
                else:
                    print(f"\n  {key}: {val}")
            print("")


if __name__ == "__main__":
    main()
