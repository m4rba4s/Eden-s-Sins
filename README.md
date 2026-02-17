# 🍎🐍 The Eden's Sins

> macOS Purple Team Assessment Framework

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-macOS-red)](MITRE_MAPPING.md)
[![License](https://img.shields.io/badge/License-Educational%20Only-yellow)](#legal-disclaimer)

## Overview

A comprehensive macOS security assessment framework that pairs **every offensive technique with its defensive counterpart**. Built for red/purple teams, security researchers, and SOC engineers who need to understand both sides of the macOS security equation.

**Target**: macOS Sonoma/Sequoia (Apple Silicon M1–M4 primary, Intel x86_64 secondary)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  THE EDEN'S SINS                         │
├──────────────┬──────────────────┬────────────────────────┤
│   OFFENSIVE  │    DETECTION     │      HARDENING         │
├──────────────┼──────────────────┼────────────────────────┤
│ tools/recon  │ sigma/ rules     │ audit_config.sh        │
│ tools/persist│ yara/ rules      │ lockdown.sh            │
│ tools/bypass │ osquery/ packs   │ nist_compliance.py     │
│ tools/privesc│                  │ profiles/*.mobileconfig│
│ tools/exfil  │                  │                        │
├──────────────┴──────────────────┴────────────────────────┤
│              demo/attack_chain.py                        │
│         Full kill chain orchestrator + slides            │
└─────────────────────────────────────────────────────────┘
```

## Kill Chain Phases

| # | Phase | Tools | ATT&CK Tactics |
|---|-------|-------|-----------------|
| 1 | **Reconnaissance** | `macos_fingerprint.py`, `keychain_dump.sh`, `log_hunter.sh`, `aslr_probe.py` | Discovery, Credential Access |
| 2 | **Defense Bypass** | `tcc_audit.py`, `gatekeeper_check.sh`, `codesign_analyzer.py` | Defense Evasion |
| 3 | **Persistence** | `launch_agent_implant.py`, `dylib_hijack_scanner.py`, `dyld_inject.sh`, `login_item_persist.py` | Persistence, Execution |
| 4 | **Privilege Escalation** | `xpc_fuzzer.py`, `suid_hunter.sh`, `symlink_race.py` | Privilege Escalation |
| 5 | **Exfiltration** | `keychain_exfil.py`, `fsevents_monitor.py`, `clipboard_sniff.py` | Collection, Exfiltration |
| 6 | **Demo** | `attack_chain.py` | Full kill chain |

## Quick Start

### Prerequisites

```bash
# On macOS target
python3 -m pip install -r requirements.txt

# For detections (any OS)
pip install sigma-cli yara-python
brew install osquery  # macOS
```

### Run Recon

```bash
# System fingerprint
python3 tools/recon/macos_fingerprint.py --output json

# Hunt for credential leaks in logs
bash tools/recon/log_hunter.sh

# Keychain enumeration
bash tools/recon/keychain_dump.sh
```

### Run Detections

```bash
# Validate Sigma rules
sigma check detections/sigma/*.yml

# Test YARA rules
yara detections/yara/*.yar /path/to/scan

# Load osquery pack
osqueryi --pack detections/osquery/macos_persistence_pack.conf
```

### Harden

```bash
# Full audit (dry-run)
bash hardening/audit_config.sh --dry-run

# Apply lockdown
sudo bash hardening/lockdown.sh
```

## Legal Disclaimer

> [!CAUTION]
> This framework is for **authorized security testing, education, and research ONLY**.
> Unauthorized use against systems you do not own or have explicit written permission
> to test is **illegal** and **unethical**. The authors assume no liability for misuse.
> Always operate within your Rules of Engagement (RoE).

## References

- [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/)
- [NIST macOS Security Compliance Project](https://github.com/usnistgov/macos_security)
- [CIS Apple macOS Benchmark](https://www.cisecurity.org/benchmark/apple_os)
- [Objective-See Tools](https://objective-see.org/tools.html)
