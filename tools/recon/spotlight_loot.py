#!/usr/bin/env python3
"""
Spotlight Loot Finder — The Eden's Sins
MITRE ATT&CK: T1083 File and Directory Discovery

Abuses macOS Spotlight index (mdfind) for instant sensitive file discovery.
Spotlight indexes the entire disk — orders of magnitude faster than `find`.

Usage:
    python3 spotlight_loot.py [--profile all] [--json] [--output loot.json]
    python3 spotlight_loot.py --profile creds
    python3 spotlight_loot.py --custom "kMDItemDisplayName == '*.env'"
    python3 spotlight_loot.py --detect
"""

import argparse, json, os, subprocess, sys, time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ─── Loot Profiles ───
# Each profile = list of (description, mdfind_query or filename_pattern)
PROFILES = {
    "creds": {
        "name": "🔑 Credentials & Secrets",
        "queries": [
            ("SSH private keys", "kMDItemDisplayName == 'id_rsa' || kMDItemDisplayName == 'id_ed25519' || kMDItemDisplayName == 'id_ecdsa'"),
            ("PEM certificates", "kMDItemDisplayName == '*.pem'"),
            ("P12/PFX keystores", "kMDItemDisplayName == '*.p12' || kMDItemDisplayName == '*.pfx'"),
            ("KeePass databases", "kMDItemDisplayName == '*.kdbx' || kMDItemDisplayName == '*.kdb'"),
            ("1Password vaults", "kMDItemDisplayName == '*.opvault' || kMDItemDisplayName == '*.agilekeychain'"),
            (".env files", "kMDItemDisplayName == '.env' || kMDItemDisplayName == '.env.local' || kMDItemDisplayName == '.env.production'"),
            ("AWS credentials", "kMDItemDisplayName == 'credentials' && kMDItemFSName == 'credentials'"),
            ("kubeconfig", "kMDItemDisplayName == 'config' && kMDItemWhereFroms == *kube*"),
            ("GPG keys", "kMDItemDisplayName == '*.gpg' || kMDItemDisplayName == 'secring*'"),
            ("htpasswd files", "kMDItemDisplayName == '.htpasswd' || kMDItemDisplayName == 'htpasswd'"),
        ],
    },
    "finance": {
        "name": "💰 Financial Documents",
        "queries": [
            ("Tax documents", "kMDItemDisplayName == '*tax*' && (kMDItemContentType == 'com.adobe.pdf' || kMDItemContentType == 'public.plain-text')"),
            ("Bank statements", "kMDItemDisplayName == '*bank*statement*'"),
            ("Invoices", "kMDItemDisplayName == '*invoice*' && kMDItemContentType == 'com.adobe.pdf'"),
            ("Crypto wallets", "kMDItemDisplayName == 'wallet.dat' || kMDItemDisplayName == '*.wallet'"),
            ("Financial spreadsheets", "kMDItemDisplayName == '*budget*' || kMDItemDisplayName == '*salary*' || kMDItemDisplayName == '*payroll*'"),
        ],
    },
    "devops": {
        "name": "⚙️ DevOps & Infrastructure",
        "queries": [
            ("Docker configs", "kMDItemDisplayName == 'docker-compose*' || kMDItemDisplayName == 'Dockerfile'"),
            ("Terraform state", "kMDItemDisplayName == '*.tfstate' || kMDItemDisplayName == '*.tfvars'"),
            ("Ansible vaults", "kMDItemDisplayName == '*vault*' && kMDItemDisplayName == '*.yml'"),
            ("Jenkins configs", "kMDItemDisplayName == 'credentials.xml' || kMDItemDisplayName == 'config.xml'"),
            ("CI/CD configs", "kMDItemDisplayName == '.gitlab-ci.yml' || kMDItemDisplayName == '.github'"),
            ("Database dumps", "kMDItemDisplayName == '*.sql' || kMDItemDisplayName == '*.dump' || kMDItemDisplayName == '*.bak'"),
            ("Shell scripts with secrets", "kMDItemDisplayName == '*.sh' && kMDItemTextContent == *password*"),
        ],
    },
    "documents": {
        "name": "📄 Sensitive Documents",
        "queries": [
            ("Confidential docs", "kMDItemDisplayName == '*confidential*' || kMDItemDisplayName == '*secret*' || kMDItemDisplayName == '*classified*'"),
            ("NDA documents", "kMDItemDisplayName == '*NDA*' || kMDItemDisplayName == '*non-disclosure*'"),
            ("Password lists", "kMDItemDisplayName == '*password*' && (kMDItemContentType == 'public.plain-text' || kMDItemDisplayName == '*.xlsx')"),
            ("VPN configs", "kMDItemDisplayName == '*.ovpn' || kMDItemDisplayName == '*.conf' && kMDItemDisplayName == '*vpn*'"),
            ("SSH configs", "kMDItemDisplayName == 'config' || kMDItemDisplayName == 'ssh_config'"),
            ("RDP files", "kMDItemDisplayName == '*.rdp'"),
        ],
    },
}

# Simple filename-based fallback queries (no Spotlight metadata operators)
SIMPLE_PATTERNS = {
    "creds": [
        ("SSH keys", ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]),
        ("PEM/P12 certs", ["*.pem", "*.p12", "*.pfx", "*.crt", "*.key"]),
        ("KeePass DB", ["*.kdbx", "*.kdb"]),
        (".env files", [".env", ".env.local", ".env.production", ".env.staging"]),
        ("AWS config", ["credentials", "*.aws"]),
        ("GPG keys", ["*.gpg", "secring.*"]),
    ],
    "finance": [
        ("Crypto wallets", ["wallet.dat", "*.wallet"]),
        ("Financial docs", ["*invoice*.pdf", "*tax*.pdf", "*bank*.pdf"]),
    ],
    "devops": [
        ("Terraform state", ["*.tfstate", "*.tfvars"]),
        ("DB dumps", ["*.sql", "*.dump", "*.sql.gz"]),
        ("Docker", ["docker-compose.yml", "docker-compose.yaml"]),
    ],
    "documents": [
        ("VPN configs", ["*.ovpn"]),
        ("RDP files", ["*.rdp"]),
        ("Password files", ["passwords.txt", "passwords.xlsx", "passwd"]),
    ],
}


def mdfind_query(query: str, limit: int = 25) -> list[str]:
    """Run mdfind Spotlight query."""
    try:
        r = subprocess.run(
            ["mdfind", query],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            results = [l for l in r.stdout.strip().splitlines() if l]
            return results[:limit]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def mdfind_name(name: str, limit: int = 25) -> list[str]:
    """Search by filename using mdfind -name."""
    try:
        r = subprocess.run(
            ["mdfind", "-name", name],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            results = [l for l in r.stdout.strip().splitlines() if l]
            return results[:limit]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def run_profile(profile_key: str) -> dict:
    """Run all queries in a profile."""
    results = {"profile": profile_key, "findings": [], "total": 0}

    simple = SIMPLE_PATTERNS.get(profile_key, [])
    for desc, patterns in simple:
        hits = []
        for pattern in patterns:
            hits.extend(mdfind_name(pattern, limit=15))

        # Deduplicate
        hits = list(dict.fromkeys(hits))

        if hits:
            results["findings"].append({
                "category": desc,
                "count": len(hits),
                "files": hits[:10],
            })
            results["total"] += len(hits)

    return results


def format_report(all_results: dict) -> str:
    """Format text report."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — Spotlight Loot Report",
        "=" * 60, "",
    ]

    total_all = 0
    for profile_key, results in all_results.items():
        profile_info = PROFILES.get(profile_key, {"name": profile_key})
        lines.append(f"  {profile_info['name']}")
        lines.append("  " + "─" * 54)

        if not results["findings"]:
            lines.append("    (nothing found)")
        else:
            for finding in results["findings"]:
                lines.append(f"    📂 {finding['category']} ({finding['count']} found)")
                for f in finding["files"][:5]:
                    size = ""
                    try:
                        s = os.path.getsize(f)
                        size = f" ({s:,} bytes)" if s > 0 else ""
                    except OSError:
                        pass
                    lines.append(f"       → {f}{size}")
                if finding["count"] > 5:
                    lines.append(f"       ... +{finding['count'] - 5} more")

        total_all += results["total"]
        lines.append("")

    lines.extend([
        "─" * 60,
        f"  Total sensitive files found: {total_all}",
        "─" * 60, "",
        "  BLUE TEAM — Detection & Hardening",
        "  " + "─" * 54, "",
        "  Detection:",
        "    • Monitor mdfind/mdls command execution by non-Finder processes",
        "    • ESF: track Spotlight query API calls (MDQuery)",
        "    • Alert on rapid mdfind queries for sensitive patterns",
        "    • osquery: SELECT * FROM mdfind WHERE query = 'kMDItemDisplayName == *.pem'", "",
        "  Hardening:",
        "    • Add sensitive directories to Spotlight Privacy exclusions",
        "    •   System Prefs → Siri & Spotlight → Privacy",
        "    • Use .metadata_never_index file in sensitive directories",
        "    • Store secrets in keychain, not files",
        "    • FileVault protects data at rest (but not from local user)",
        "    • Use MDM to restrict mdfind/Spotlight access",
        "=" * 60,
    ])

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Spotlight Loot — The Eden's Sins")
    p.add_argument(
        "--profile", choices=list(PROFILES.keys()) + ["all"], default="all",
        help="Loot profile to run",
    )
    p.add_argument("--custom", help="Custom mdfind query")
    p.add_argument("--json", action="store_true")
    p.add_argument("--output", help="Save results to file")
    p.add_argument("--detect", action="store_true")
    args = p.parse_args()

    if args.detect:
        print("  Monitor mdfind execution, Spotlight Privacy list, MDQuery API calls")
        print("  Harden: add .metadata_never_index, exclude dirs in Spotlight Privacy")
        return

    if args.custom:
        results = mdfind_query(args.custom, limit=50)
        for r in results:
            print(f"  {r}")
        print(f"\n  Total: {len(results)}")
        return

    profiles = list(PROFILES.keys()) if args.profile == "all" else [args.profile]
    all_results = {}

    print("[*] THE EDEN'S SINS — Spotlight Loot Finder")

    for pk in profiles:
        print(f"  Scanning: {PROFILES[pk]['name']}...")
        all_results[pk] = run_profile(pk)

    if args.json:
        out = json.dumps(all_results, indent=2)
    else:
        out = format_report(all_results)

    print(out)

    if args.output:
        Path(args.output).write_text(out)
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
