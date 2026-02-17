# MITRE ATT&CK Mapping — The Eden's Sins

> All techniques mapped to [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)

## Phase 1: Reconnaissance

| Tool | Technique ID | Technique Name | Data Sources | Mitigations |
|------|-------------|----------------|--------------|-------------|
| `macos_fingerprint.py` | T1082 | System Information Discovery | Process monitoring, Command-line | Restrict admin tools |
| `keychain_dump.sh` | T1555.001 | Credentials from Password Stores: Keychain | Process monitoring, File access | Keychain ACLs, strong master password |
| `log_hunter.sh` | T1005 | Data from Local System | File monitoring | Log rotation, redaction policies |
| `aslr_probe.py` | T1057 | Process Discovery | Process monitoring | ASLR hardening, PIE enforcement |

## Phase 2: Defense Bypass

| Tool | Technique ID | Technique Name | Data Sources | Mitigations |
|------|-------------|----------------|--------------|-------------|
| `tcc_audit.py` | T1548 | Abuse Elevation Control Mechanism | TCC.db monitoring | MDM-managed TCC, least privilege |
| `gatekeeper_check.sh` | T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | Quarantine xattr, log | Strict Gatekeeper policy, notarization |
| `codesign_analyzer.py` | T1553.002 | Subvert Trust Controls: Code Signing | Code signing validation | Hardened Runtime mandatory |

## Phase 3: Persistence

| Tool | Technique ID | Technique Name | Data Sources | Mitigations |
|------|-------------|----------------|--------------|-------------|
| `launch_agent_implant.py` | T1543.001 / T1543.004 | Create/Modify System Process: Launch Agent/Daemon | File monitoring, launchctl | Restrict LaunchAgent dirs, monitoring |
| `dylib_hijack_scanner.py` | T1574.004 | Hijack Execution Flow: Dylib Hijacking | Module loads, File monitoring | Hardened Runtime, @rpath cleanup |
| `dyld_inject.sh` | T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | Environment variables, Process monitoring | SIP enabled, Hardened Runtime |
| `login_item_persist.py` | T1547.015 | Boot/Logon Autostart: Login Items | Login item changes | MDM-managed login items |

## Phase 4: Privilege Escalation

| Tool | Technique ID | Technique Name | Data Sources | Mitigations |
|------|-------------|----------------|--------------|-------------|
| `xpc_fuzzer.py` | T1559 | Inter-Process Communication | XPC connections, Mach messages | Input validation, entitlement checks |
| `suid_hunter.sh` | T1548.001 | Abuse Elevation Control: Setuid/Setgid | File monitoring | Remove unnecessary SUID bits |
| `symlink_race.py` | T1068 | Exploitation for Privilege Escalation | File system events | Atomic file ops, O_NOFOLLOW |

## Phase 5: Exfiltration

| Tool | Technique ID | Technique Name | Data Sources | Mitigations |
|------|-------------|----------------|--------------|-------------|
| `keychain_exfil.py` | T1555.001 | Credentials from Password Stores: Keychain | Keychain access events | Strong master password, biometric lock |
| `fsevents_monitor.py` | T1083 | File and Directory Discovery | FSEvents logs | TCC restrictions, endpoint monitoring |
| `clipboard_sniff.py` | T1115 | Clipboard Data | Pasteboard access | TCC for clipboard, clipboard timeout |

## Detection Coverage Matrix

```
                    Sigma  YARA  osquery
Recon                 ✓      -      ✓
Persistence           ✓      ✓      ✓
Defense Bypass        ✓      -      ✓
Privesc               ✓      -      ✓
Exfiltration          ✓      ✓      ✓
```
