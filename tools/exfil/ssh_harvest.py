#!/usr/bin/env python3
"""
SSH Key Harvester — The Eden's Sins
MITRE ATT&CK: T1552.004 Unsecured Credentials: Private Keys

Scans for SSH keys, checks passphrase protection, parses known_hosts
and SSH config for lateral movement targets.

Usage:
    python3 ssh_harvest.py [--scan-all] [--json] [--detect]
"""

import argparse, json, os, re, subprocess, sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class SSHKey:
    path: str
    key_type: str = ""       # rsa, ed25519, ecdsa
    bits: int = 0
    has_passphrase: bool = True
    has_pub_key: bool = False
    comment: str = ""
    risk: str = "LOW"


@dataclass
class SSHTarget:
    host: str
    user: str = ""
    port: int = 22
    identity_file: str = ""
    source: str = ""  # config, known_hosts, history


def find_ssh_keys(scan_all=False):
    """Find SSH private keys."""
    keys = []
    search_dirs = [Path.home() / ".ssh"]

    if scan_all:
        search_dirs.extend([
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path("/tmp"),
        ])

    key_headers = {
        b"-----BEGIN OPENSSH PRIVATE KEY-----": "openssh",
        b"-----BEGIN RSA PRIVATE KEY-----": "rsa",
        b"-----BEGIN EC PRIVATE KEY-----": "ecdsa",
        b"-----BEGIN DSA PRIVATE KEY-----": "dsa",
        b"-----BEGIN PRIVATE KEY-----": "pkcs8",
    }

    for sdir in search_dirs:
        if not sdir.exists():
            continue

        for fpath in sdir.rglob("*"):
            if not fpath.is_file() or fpath.stat().st_size > 50000:
                continue
            if fpath.suffix in (".pub", ".known_hosts", ".log"):
                continue

            try:
                with open(fpath, "rb") as f:
                    head = f.read(100)

                for header, ktype in key_headers.items():
                    if header in head:
                        key = SSHKey(
                            path=str(fpath),
                            key_type=ktype,
                        )

                        # Check if pub key exists alongside
                        pub = Path(str(fpath) + ".pub")
                        key.has_pub_key = pub.exists()

                        # Check passphrase with ssh-keygen
                        try:
                            r = subprocess.run(
                                ["ssh-keygen", "-y", "-P", "", "-f", str(fpath)],
                                capture_output=True, timeout=5,
                            )
                            key.has_passphrase = r.returncode != 0
                        except Exception:
                            key.has_passphrase = True  # Assume protected

                        if not key.has_passphrase:
                            key.risk = "CRITICAL"
                        else:
                            key.risk = "LOW"

                        # Get key info
                        try:
                            r = subprocess.run(
                                ["ssh-keygen", "-l", "-f", str(fpath)],
                                capture_output=True, text=True, timeout=5,
                            )
                            if r.returncode == 0:
                                parts = r.stdout.strip().split()
                                if len(parts) >= 2:
                                    key.bits = int(parts[0])
                                if len(parts) >= 4:
                                    key.comment = parts[2]
                        except Exception:
                            pass

                        keys.append(key)
                        break
            except (PermissionError, OSError):
                continue

    return keys


def parse_ssh_config():
    """Parse ~/.ssh/config for targets."""
    targets = []
    config = Path.home() / ".ssh" / "config"
    if not config.exists():
        return targets

    current = {}
    for line in config.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if line.lower().startswith("host "):
            if current.get("host"):
                targets.append(SSHTarget(
                    host=current.get("hostname", current["host"]),
                    user=current.get("user", ""),
                    port=int(current.get("port", 22)),
                    identity_file=current.get("identityfile", ""),
                    source="ssh_config",
                ))
            host_val = line.split(None, 1)[1]
            current = {"host": host_val}
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                current[parts[0].lower()] = parts[1]

    if current.get("host"):
        targets.append(SSHTarget(
            host=current.get("hostname", current["host"]),
            user=current.get("user", ""),
            port=int(current.get("port", 22)),
            identity_file=current.get("identityfile", ""),
            source="ssh_config",
        ))

    return targets


def parse_known_hosts():
    """Parse known_hosts for previously connected hosts."""
    targets = []
    kh = Path.home() / ".ssh" / "known_hosts"
    if not kh.exists():
        return targets

    for line in kh.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        host_part = line.split()[0] if line.split() else ""
        # Handle hashed known_hosts
        if host_part.startswith("|"):
            targets.append(SSHTarget(host="[hashed]", source="known_hosts"))
        else:
            for h in host_part.split(","):
                h = h.strip("[]")
                port = 22
                if ":" in h and not h.startswith("["):
                    parts = h.rsplit(":", 1)
                    h = parts[0]
                    try:
                        port = int(parts[1])
                    except ValueError:
                        pass
                targets.append(SSHTarget(host=h, port=port, source="known_hosts"))

    return targets


def format_report(keys, targets):
    lines = [
        "=" * 55,
        "  THE EDEN'S SINS — SSH Reconnaissance Report",
        "=" * 55, "",
    ]

    # Keys
    lines.append(f"  🔑 SSH Keys Found: {len(keys)}")
    lines.append("  " + "─" * 51)
    for k in keys:
        icon = "🔴" if k.risk == "CRITICAL" else "🟢"
        passphrase = "NO PASSPHRASE!" if not k.has_passphrase else "protected"
        lines.append(f"    {icon} {k.path}")
        lines.append(f"        Type: {k.key_type} | Bits: {k.bits} | {passphrase}")
        if k.comment:
            lines.append(f"        Comment: {k.comment}")

    # Targets
    if targets:
        lines.extend(["", f"  🎯 Lateral Movement Targets: {len(targets)}"])
        lines.append("  " + "─" * 51)

        config_targets = [t for t in targets if t.source == "ssh_config"]
        kh_targets = [t for t in targets if t.source == "known_hosts"]

        if config_targets:
            lines.append("    From SSH config:")
            for t in config_targets[:15]:
                user = f"{t.user}@" if t.user else ""
                lines.append(f"      → {user}{t.host}:{t.port}")

        if kh_targets:
            lines.append(f"    From known_hosts ({len(kh_targets)} entries):")
            unique = set(t.host for t in kh_targets if t.host != "[hashed]")
            hashed = sum(1 for t in kh_targets if t.host == "[hashed]")
            for h in sorted(unique)[:15]:
                lines.append(f"      → {h}")
            if hashed:
                lines.append(f"      + {hashed} hashed entries")

    lines.extend([
        "", "─" * 55,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 55, "",
        "  Detection:",
        "    • Monitor reads on ~/.ssh/ directory",
        "    • Alert on ssh-keygen -y (passphrase check)",
        "    • Track SSH key file access from non-SSH processes", "",
        "  Hardening:",
        "    • Require passphrase on ALL private keys",
        "    • Use Ed25519 keys (modern, fast, secure)",
        "    • Enable SSH agent with confirmation (-c flag)",
        "    • Remove unused keys and known_hosts entries",
        "    • Use SSH certificates instead of static keys",
        "=" * 55,
    ])

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="SSH Harvester — The Eden's Sins")
    p.add_argument("--scan-all", action="store_true", help="Scan beyond ~/.ssh")
    p.add_argument("--json", action="store_true")
    p.add_argument("--detect", action="store_true")
    p.add_argument("--output", help="Save to file")
    args = p.parse_args()

    if args.detect:
        print("  Monitor ~/.ssh access, ssh-keygen -y probing, bulk key reads")
        print("  Harden: passphrase all keys, Ed25519, SSH certs, agent -c")
        return

    keys = find_ssh_keys(args.scan_all)
    config_targets = parse_ssh_config()
    kh_targets = parse_known_hosts()
    all_targets = config_targets + kh_targets

    if args.json:
        out = json.dumps({
            "keys": [asdict(k) for k in keys],
            "targets": [asdict(t) for t in all_targets],
        }, indent=2)
    else:
        out = format_report(keys, all_targets)

    print(out)
    if args.output:
        Path(args.output).write_text(out)
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
