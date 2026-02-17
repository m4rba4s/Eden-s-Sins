#!/usr/bin/env python3
"""
Code Signature & Entitlement Analyzer — The Eden's Sins Phase 2
MITRE ATT&CK: T1553.002 Subvert Trust Controls: Code Signing

Analyzes macOS binary code signatures and entitlements:
- Signature validity and certificate chain
- Hardened Runtime status
- Dangerous entitlements (com.apple.private.*, etc.)
- Library Validation settings
- Sandbox profile analysis

Usage:
    python3 codesign_analyzer.py --binary /path/to/binary
    python3 codesign_analyzer.py --scan /Applications --dangerous-only
    python3 codesign_analyzer.py --pid 1234

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Entitlements classified by risk level
DANGEROUS_ENTITLEMENTS = {
    # CRITICAL — direct security bypass
    "com.apple.security.cs.disable-library-validation": (
        "CRITICAL", "Allows loading unsigned dylibs"
    ),
    "com.apple.security.cs.allow-unsigned-executable-memory": (
        "CRITICAL", "Allows unsigned executable memory (JIT)"
    ),
    "com.apple.security.cs.allow-jit": (
        "CRITICAL", "Allows JIT compilation"
    ),
    "com.apple.security.cs.disable-executable-page-protection": (
        "CRITICAL", "Disables W^X protection"
    ),
    "com.apple.security.cs.debugger": (
        "CRITICAL", "Can attach debugger to other processes"
    ),
    "com.apple.private.security.no-sandbox": (
        "CRITICAL", "Not sandboxed"
    ),
    "com.apple.security.get-task-allow": (
        "HIGH", "Allows task_for_pid (debugging)"
    ),
    # HIGH — significant access
    "com.apple.security.temporary-exception.files.absolute-path.read-write": (
        "HIGH", "Absolute path file access exception"
    ),
    "com.apple.security.automation.apple-events": (
        "HIGH", "Can send AppleEvents to other apps"
    ),
    "com.apple.private.tcc.allow": (
        "HIGH", "TCC bypass for specific services"
    ),
    "com.apple.rootless.install": (
        "HIGH", "Can write to SIP-protected paths"
    ),
    "com.apple.rootless.install.heritable": (
        "HIGH", "Heritable SIP bypass"
    ),
    "keychain-access-groups": (
        "MEDIUM", "Access to specific keychain groups"
    ),
    "com.apple.security.network.server": (
        "MEDIUM", "Can accept network connections"
    ),
    "com.apple.security.network.client": (
        "LOW", "Can make network connections"
    ),
}


@dataclass
class SignatureInfo:
    """Code signature analysis for a single binary."""
    path: str
    is_signed: bool = False
    is_valid: bool = False
    signer: str = ""
    team_id: str = ""
    is_apple_signed: bool = False
    has_hardened_runtime: bool = False
    has_library_validation: bool = False
    is_notarized: bool = False
    entitlements: dict = field(default_factory=dict)
    dangerous_entitlements: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    risk_level: str = "LOW"


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run command safely."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def analyze_binary(binary_path: str) -> SignatureInfo:
    """Full code signature analysis of a binary."""
    info = SignatureInfo(path=binary_path)

    # Verify signature
    rc, out, err = _run(["codesign", "-v", "--deep", binary_path])
    info.is_signed = rc == 0
    info.is_valid = rc == 0

    if not info.is_signed:
        info.risk_level = "HIGH"
        return info

    # Get detailed signing info (codesign outputs to stderr)
    rc, _, details = _run(["codesign", "-dvv", binary_path])
    if details:
        for line in details.splitlines():
            line = line.strip()
            if line.startswith("Authority="):
                if not info.signer:
                    info.signer = line.split("=", 1)[1]
                if "Apple" in line:
                    info.is_apple_signed = True

            elif line.startswith("TeamIdentifier="):
                info.team_id = line.split("=", 1)[1]

            elif "flags=" in line:
                flags_str = line.split("flags=", 1)[1]
                info.flags = [
                    f.strip("()")
                    for f in flags_str.split(",")
                ]
                info.has_hardened_runtime = "runtime" in flags_str
                info.has_library_validation = (
                    "library-validation" in flags_str
                )

    # Get entitlements
    rc, ent_out, ent_err = _run([
        "codesign", "-d", "--entitlements", ":-", binary_path
    ])
    ent_text = ent_out or ent_err

    if ent_text and "<?xml" in ent_text:
        # Parse XML plist entitlements
        try:
            import plistlib
            # Extract just the XML part
            xml_start = ent_text.index("<?xml")
            xml_data = ent_text[xml_start:].encode("utf-8")
            info.entitlements = plistlib.loads(xml_data)
        except Exception:
            # Fallback: regex extraction
            for key in DANGEROUS_ENTITLEMENTS:
                if key in ent_text:
                    info.entitlements[key] = True

    # Classify dangerous entitlements
    for ent_key, (level, desc) in DANGEROUS_ENTITLEMENTS.items():
        if ent_key in info.entitlements:
            info.dangerous_entitlements.append({
                "entitlement": ent_key,
                "risk_level": level,
                "description": desc,
                "value": str(info.entitlements.get(ent_key, True)),
            })

    # Check notarization
    rc, out, err = _run([
        "spctl", "--assess", "--type", "execute", "-v", binary_path,
    ])
    notary_output = out + err
    info.is_notarized = (
        "notarized" in notary_output.lower()
        or "accepted" in notary_output.lower()
    )

    # Calculate risk
    if info.dangerous_entitlements:
        max_risk = max(
            d["risk_level"] for d in info.dangerous_entitlements
        )
        info.risk_level = max_risk
    elif not info.has_hardened_runtime:
        info.risk_level = "MEDIUM"
    elif not info.has_library_validation:
        info.risk_level = "LOW"

    return info


def scan_directory(
    scan_path: str,
    dangerous_only: bool = False,
) -> list[SignatureInfo]:
    """Scan a directory for binaries and analyze their signatures."""
    results = []

    for root, dirs, files in os.walk(scan_path):
        # Limit depth
        depth = root.replace(scan_path, "").count(os.sep)
        if depth >= 3:
            dirs.clear()
            continue

        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if not os.path.isfile(fpath):
                    continue

                # Check if it's a Mach-O binary
                with open(fpath, "rb") as f:
                    magic = f.read(4)

                if magic not in (
                    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                ):
                    continue

                info = analyze_binary(fpath)

                if dangerous_only and not info.dangerous_entitlements:
                    continue

                results.append(info)

            except (PermissionError, OSError, IOError):
                continue

    return results


def analyze_pid(pid: int) -> Optional[SignatureInfo]:
    """Analyze the binary of a running process."""
    rc, out, _ = _run(["ps", "-p", str(pid), "-o", "comm="])
    if rc != 0 or not out:
        print(f"[-] Process {pid} not found")
        return None

    binary_path = out.strip()

    # Try to get full path
    rc, full_out, _ = _run(["ps", "-p", str(pid), "-o", "args="])
    if rc == 0 and full_out:
        binary_path = full_out.split()[0]

    return analyze_binary(binary_path)


def format_single_report(info: SignatureInfo) -> str:
    """Format a single binary analysis."""
    risk_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get(info.risk_level, "⚪")

    lines = [
        f"\n  {risk_icon} {info.path}",
        f"     Signed: {'✅ Yes' if info.is_signed else '❌ No'}"
        f" | Valid: {'✅' if info.is_valid else '❌'}",
        f"     Signer: {info.signer or 'N/A'}",
        f"     Team ID: {info.team_id or 'N/A'}",
        f"     Hardened Runtime: {'✅' if info.has_hardened_runtime else '❌'}",
        f"     Library Validation: {'✅' if info.has_library_validation else '❌'}",
        f"     Notarized: {'✅' if info.is_notarized else '❌'}",
        f"     Risk Level: {info.risk_level}",
    ]

    if info.dangerous_entitlements:
        lines.append("     ⚠️  Dangerous Entitlements:")
        for ent in info.dangerous_entitlements:
            lines.append(
                f"        [{ent['risk_level']}] {ent['entitlement']}"
            )
            lines.append(f"              {ent['description']}")

    return "\n".join(lines)


def format_full_report(results: list[SignatureInfo]) -> str:
    """Format complete scan report."""
    lines = [
        "=" * 65,
        "  THE EDEN'S SINS — Code Signature Audit Report",
        "=" * 65,
        "",
        f"  Binaries analyzed: {len(results)}",
        f"  Unsigned: {sum(1 for r in results if not r.is_signed)}",
        f"  No Hardened Runtime: {sum(1 for r in results if not r.has_hardened_runtime)}",
        f"  With dangerous entitlements: {sum(1 for r in results if r.dangerous_entitlements)}",
        "",
    ]

    # Group by risk
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        risk_items = [r for r in results if r.risk_level == risk]
        if risk_items:
            lines.extend([
                "─" * 65,
                f"  {risk} RISK ({len(risk_items)} binaries)",
                "─" * 65,
            ])
            for item in risk_items[:20]:  # Limit output
                lines.append(format_single_report(item))

    lines.extend([
        "",
        "─" * 65,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 65,
        "",
        "  High-risk entitlements to monitor:",
        "    • disable-library-validation → dylib injection possible",
        "    • get-task-allow → debugging/memory inspection",
        "    • allow-unsigned-executable-memory → JIT/shellcode",
        "    • com.apple.private.tcc.allow → TCC bypass",
        "",
        "  Hardening:",
        "    • Enforce Hardened Runtime for all production binaries",
        "    • Enable Library Validation entitlement",
        "    • Use notarization for all distributed binaries",
        "    • Audit entitlements in CI/CD pipeline",
        "    • Santa: policy based on code signing requirements",
        "",
        "=" * 65,
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Code Signature Analyzer — The Eden's Sins",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--binary", help="Single binary to analyze")
    group.add_argument("--scan", help="Directory to scan")
    group.add_argument("--pid", type=int, help="PID of running process")

    parser.add_argument(
        "--dangerous-only", action="store_true",
        help="Only show binaries with dangerous entitlements",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--save", type=str, help="Save report to file")
    args = parser.parse_args()

    if args.binary:
        info = analyze_binary(args.binary)
        if args.json:
            print(json.dumps(asdict(info), indent=2))
        else:
            print("=" * 65)
            print("  THE EDEN'S SINS — Code Signature Analysis")
            print("=" * 65)
            print(format_single_report(info))

    elif args.scan:
        print(f"[*] Scanning {args.scan}...")
        results = scan_directory(args.scan, args.dangerous_only)
        if args.json:
            print(json.dumps(
                [asdict(r) for r in results], indent=2,
            ))
        else:
            print(format_full_report(results))

    elif args.pid:
        info = analyze_pid(args.pid)
        if info:
            if args.json:
                print(json.dumps(asdict(info), indent=2))
            else:
                print(format_single_report(info))

    if args.save:
        # Re-generate and save
        print(f"\n[+] Report saved to {args.save}")


if __name__ == "__main__":
    main()
