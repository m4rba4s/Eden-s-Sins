#!/usr/bin/env python3
"""
Dylib Hijack Scanner — The Eden's Sins Phase 3
MITRE ATT&CK: T1574.004 Dylib Hijacking

Scans macOS binaries for weak dylib references that can be hijacked:
- @rpath references without Hardened Runtime
- Relative path dylib loads
- Missing dylibs referenced by binaries
- Writable dylib search paths

Usage:
    python3 dylib_hijack_scanner.py [--path /Applications] [--deep] [--json]

Author: The Eden's Sins / Purple Team
"""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class DylibReference:
    """A single dylib reference from a binary."""
    binary: str
    dylib_path: str
    load_type: str  # @rpath, @loader_path, @executable_path, absolute, relative
    exists: bool = True
    writable: bool = False
    hijackable: bool = False
    reason: str = ""


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_path: str = ""
    binaries_scanned: int = 0
    total_dylib_refs: int = 0
    hijackable_refs: list = field(default_factory=list)
    missing_dylibs: list = field(default_factory=list)
    weak_rpaths: list = field(default_factory=list)
    hardened_runtime_missing: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run command safely."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return -1, "", str(e)


def is_macho_binary(path: str) -> bool:
    """Check if a file is a Mach-O binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            # MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT
            return magic in (
                b"\xfe\xed\xfa\xce",  # MH_MAGIC
                b"\xce\xfa\xed\xfe",  # MH_CIGAM
                b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
                b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
                b"\xca\xfe\xba\xbe",  # FAT_MAGIC
                b"\xbe\xba\xfe\xca",  # FAT_CIGAM
            )
    except (IOError, PermissionError):
        return False


def check_hardened_runtime(binary_path: str) -> bool:
    """Check if binary has Hardened Runtime enabled."""
    rc, out, _ = _run(["codesign", "-dvv", binary_path])
    if rc != 0:
        # Check stderr (codesign outputs to stderr)
        _, _, err = _run(["codesign", "-dvv", binary_path])
        return "runtime" in err.lower()
    return "runtime" in out.lower()


def get_rpaths(binary_path: str) -> list[str]:
    """Extract @rpath entries from binary."""
    rc, out, _ = _run(["otool", "-l", binary_path])
    if rc != 0:
        return []

    rpaths = []
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "cmd LC_RPATH" in line:
            # Next few lines contain the path
            for j in range(i + 1, min(i + 5, len(lines))):
                if "path" in lines[j]:
                    match = re.search(r"path\s+(\S+)", lines[j])
                    if match:
                        rpaths.append(match.group(1))
                    break
    return rpaths


def get_dylib_deps(binary_path: str) -> list[str]:
    """Get dylib dependencies from binary."""
    rc, out, _ = _run(["otool", "-L", binary_path])
    if rc != 0:
        return []

    deps = []
    for line in out.splitlines()[1:]:  # Skip first line (binary name)
        line = line.strip()
        if line:
            # Extract path before version info
            match = re.match(r"(\S+)", line)
            if match:
                deps.append(match.group(1))
    return deps


def resolve_rpath(
    rpath_ref: str,
    binary_path: str,
    rpaths: list[str],
) -> tuple[Optional[str], bool]:
    """
    Resolve an @rpath reference.
    Returns: (resolved_path or None, is_hijackable)
    """
    dylib_name = rpath_ref.replace("@rpath/", "")
    binary_dir = os.path.dirname(binary_path)

    for rpath in rpaths:
        # Resolve @loader_path and @executable_path in rpaths
        resolved_rpath = rpath
        resolved_rpath = resolved_rpath.replace(
            "@loader_path", binary_dir
        )
        resolved_rpath = resolved_rpath.replace(
            "@executable_path", binary_dir
        )

        candidate = os.path.join(resolved_rpath, dylib_name)
        if os.path.exists(candidate):
            return candidate, False

    # Not found in any rpath — potentially hijackable
    # Check if we can write to any rpath directory
    for rpath in rpaths:
        resolved_rpath = rpath.replace("@loader_path", binary_dir)
        resolved_rpath = resolved_rpath.replace(
            "@executable_path", binary_dir
        )
        if os.path.isdir(resolved_rpath):
            if os.access(resolved_rpath, os.W_OK):
                return None, True

    return None, True  # Missing and potentially exploitable


def check_dir_writable(path: str) -> bool:
    """Check if a directory is writable by current user."""
    return os.path.isdir(path) and os.access(path, os.W_OK)


def scan_binary(binary_path: str, result: ScanResult) -> None:
    """Scan a single binary for hijackable dylibs."""
    deps = get_dylib_deps(binary_path)
    rpaths = get_rpaths(binary_path)
    has_hardened = check_hardened_runtime(binary_path)

    if not has_hardened:
        result.hardened_runtime_missing.append(binary_path)

    for dep in deps:
        result.total_dylib_refs += 1

        if dep.startswith("@rpath/"):
            resolved, hijackable = resolve_rpath(dep, binary_path, rpaths)
            ref = DylibReference(
                binary=binary_path,
                dylib_path=dep,
                load_type="@rpath",
                exists=resolved is not None,
                hijackable=hijackable and not has_hardened,
            )
            if hijackable and not has_hardened:
                ref.reason = (
                    "Missing dylib with writable @rpath dir, "
                    "no Hardened Runtime"
                )
                result.hijackable_refs.append(asdict(ref))
            if not resolved:
                result.missing_dylibs.append(asdict(ref))

        elif dep.startswith("@loader_path/"):
            binary_dir = os.path.dirname(binary_path)
            actual = dep.replace("@loader_path", binary_dir)
            writable = check_dir_writable(os.path.dirname(actual))
            ref = DylibReference(
                binary=binary_path,
                dylib_path=dep,
                load_type="@loader_path",
                exists=os.path.exists(actual),
                writable=writable,
                hijackable=writable and not os.path.exists(actual),
            )
            if ref.hijackable:
                ref.reason = "Writable @loader_path with missing dylib"
                result.hijackable_refs.append(asdict(ref))

        elif dep.startswith("@executable_path/"):
            # Similar to @loader_path
            pass

        elif not dep.startswith("/"):
            # Relative path — red flag
            ref = DylibReference(
                binary=binary_path,
                dylib_path=dep,
                load_type="relative",
                hijackable=True,
                reason="Relative dylib path — trivially hijackable via CWD",
            )
            result.hijackable_refs.append(asdict(ref))

    # Check rpaths for writable entries
    for rpath in rpaths:
        binary_dir = os.path.dirname(binary_path)
        resolved = rpath.replace("@loader_path", binary_dir)
        resolved = resolved.replace("@executable_path", binary_dir)
        if os.path.isdir(resolved) and os.access(resolved, os.W_OK):
            result.weak_rpaths.append({
                "binary": binary_path,
                "rpath": rpath,
                "resolved": resolved,
                "reason": "Writable @rpath directory — dylib planting possible",
            })


def find_binaries(scan_path: str, deep: bool = False) -> list[str]:
    """Find Mach-O binaries in scan path."""
    binaries = []
    max_depth = 5 if deep else 3

    for root, dirs, files in os.walk(scan_path):
        # Depth check
        depth = root.replace(scan_path, "").count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue

        # Skip system protected dirs
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", "__pycache__"}
        ]

        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if os.path.isfile(fpath) and is_macho_binary(fpath):
                    binaries.append(fpath)
            except (PermissionError, OSError):
                continue

    return binaries


def format_text_report(result: ScanResult) -> str:
    """Format scan result as text."""
    lines = [
        "=" * 65,
        "  THE EDEN'S SINS — Dylib Hijack Scan Report",
        "=" * 65,
        "",
        f"  Scan path          : {result.scan_path}",
        f"  Binaries scanned   : {result.binaries_scanned}",
        f"  Total dylib refs   : {result.total_dylib_refs}",
        f"  Hijackable refs    : {len(result.hijackable_refs)}",
        f"  Missing dylibs     : {len(result.missing_dylibs)}",
        f"  Weak rpaths        : {len(result.weak_rpaths)}",
        f"  No Hardened Runtime: {len(result.hardened_runtime_missing)}",
        "",
    ]

    if result.hijackable_refs:
        lines.extend([
            "─" * 65,
            "  🔴 HIJACKABLE DYLIB REFERENCES",
            "─" * 65,
        ])
        for ref in result.hijackable_refs:
            lines.append(f"\n  Binary: {ref['binary']}")
            lines.append(f"  Dylib : {ref['dylib_path']}")
            lines.append(f"  Type  : {ref['load_type']}")
            lines.append(f"  Reason: {ref['reason']}")

    if result.weak_rpaths:
        lines.extend([
            "",
            "─" * 65,
            "  🟡 WRITABLE @RPATH DIRECTORIES",
            "─" * 65,
        ])
        for rp in result.weak_rpaths:
            lines.append(f"\n  Binary  : {rp['binary']}")
            lines.append(f"  Rpath   : {rp['rpath']}")
            lines.append(f"  Resolved: {rp['resolved']}")

    lines.extend([
        "",
        "─" * 65,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 65,
        "",
        "  Detection:",
        "    • Monitor dylib loads from unusual paths (ESF/dtrace)",
        "    • Alert on new files in @rpath directories",
        "    • Use BlockBlock to monitor persistence+injection",
        "    • osquery: SELECT * FROM process_open_files WHERE path LIKE '%.dylib'",
        "",
        "  Hardening:",
        "    • Enable Hardened Runtime for all binaries",
        "    • Remove unnecessary @rpath entries",
        "    • Use absolute paths for dylib references",
        "    • Sign binaries with Library Validation entitlement",
        "    • Restrict dylib loading via AMFI (Apple Mobile File Integrity)",
        "",
        "=" * 65,
    ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dylib Hijack Scanner — The Eden's Sins",
    )
    parser.add_argument(
        "--path", default="/Applications",
        help="Path to scan (default: /Applications)",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="Deep scan (more subdirectory levels)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save report to file",
    )
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"[-] Path not found: {args.path}")
        sys.exit(1)

    result = ScanResult(scan_path=args.path)

    print(f"[*] Scanning {args.path} for hijackable dylib references...")
    print(f"[*] Deep mode: {args.deep}")
    print()

    binaries = find_binaries(args.path, args.deep)
    result.binaries_scanned = len(binaries)
    print(f"[+] Found {len(binaries)} Mach-O binaries")

    for i, binary in enumerate(binaries):
        if (i + 1) % 50 == 0:
            print(f"  [{i + 1}/{len(binaries)}] scanning...")
        scan_binary(binary, result)

    if args.json:
        output = json.dumps(asdict(result), indent=2, ensure_ascii=False)
    else:
        output = format_text_report(result)

    print(output)

    if args.save:
        Path(args.save).write_text(output, encoding="utf-8")
        print(f"\n[+] Report saved to {args.save}")


if __name__ == "__main__":
    main()
