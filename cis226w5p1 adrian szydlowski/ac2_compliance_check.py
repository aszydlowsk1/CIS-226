# -*- coding: utf-8 -*-
"""
Created on Sun Nov 22 16:32:44 2026

@author: h31sy
"""

#!/usr/bin/env python3
"""
ac2_compliance_check.py
Checks a Windows computer against technical parts of NIST SP 800-53 control
AC-2 (Account Management) and its common enhancements.

Checks performed
  AC-2(a)(c)   Inventory of local accounts (enabled / disabled)
  AC-2(f)      Default / guest accounts are disabled
  AC-2(3)      Inactive accounts are disabled (default: 90 days)
  AC-2(7)      Privileged (Administrators) membership is small and reviewable
  AC-2 / IA-5  Enabled accounts require a password; password expiry is set
  AC-2(4)      Account-management auditing is turned on
  AC-2(5)      Session inactivity lock/logout is configured (default: 15 min)

Usage (run from an elevated/Administrator prompt for best results):
  python ac2_compliance_check.py
  python ac2_compliance_check.py --inactive-days 60 --max-admins 2 --output report.json

Exit codes: 0 = no failures, 1 = one or more FAIL findings, 2 = unsupported OS
NOTE: Automated checks cover only the technical portion of AC-2. Procedural
parts (account approval, notifications, account-type definitions) need manual
evidence.
"""

import argparse
import csv
import ctypes
import io
import json
import platform
import socket
import subprocess
import sys
from datetime import datetime

try:
    import winreg  # Windows-only standard library module
except ImportError:
    winreg = None

DATE_FMT = "%Y-%m-%dT%H:%M:%S"
ADMIN_GROUP_SID = "S-1-5-32-544"  # well-known SID, works on any Windows language
GUID_USER_ACCT_MGMT = "{0CCE9235-69AE-11D9-BED3-505054503030}"
GUID_SEC_GROUP_MGMT = "{0CCE9237-69AE-11D9-BED3-505054503030}"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def finding(fid, control, check, status, detail):
    """Build one result record. status = PASS | FAIL | WARN | INFO | ERROR."""
    return {"id": fid, "control": control, "check": check,
            "status": status, "detail": detail}


def is_admin():
    """True if the script is running with Administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(command):
    """Run a PowerShell command and return its stdout text."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, timeout=90)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed")
    return result.stdout


def ps_json(command):
    """Run PowerShell, parse JSON output, and always return a list."""
    out = run_powershell(command).strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]  # single object -> list


def parse_dt(text):
    return datetime.strptime(text, DATE_FMT) if text else None


# ----------------------------------------------------------------------------
# Data collection
# ----------------------------------------------------------------------------
def get_local_users():
    def dt(prop):
        return ("@{n='%s';e={if($_.%s){$_.%s.ToString('yyyy-MM-ddTHH:mm:ss')}"
                "else{$null}}}" % (prop, prop, prop))
    cmd = ("Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, "
           "@{n='Sid';e={$_.SID.Value}}, %s, %s, %s | ConvertTo-Json -Depth 3"
           % (dt("LastLogon"), dt("PasswordExpires"), dt("AccountExpires")))
    users = ps_json(cmd)
    for u in users:
        u["LastLogonDt"] = parse_dt(u.get("LastLogon"))
    return users


def get_admin_members():
    cmd = ("Get-LocalGroupMember -SID %s | Select-Object Name, ObjectClass, "
           "PrincipalSource | ConvertTo-Json -Depth 3" % ADMIN_GROUP_SID)
    return ps_json(cmd)


# ----------------------------------------------------------------------------
# Individual checks (each returns a finding dict)
# ----------------------------------------------------------------------------
def check_inventory(users):
    enabled = [u for u in users if u["Enabled"]]
    disabled = len(users) - len(enabled)
    return finding("AC2-INV", "AC-2(a),(c)", "Account inventory", "INFO",
                   "%d local accounts: %d enabled, %d disabled. "
                   "Enabled: %s" % (len(users), len(enabled), disabled,
                                    ", ".join(u["Name"] for u in enabled) or "none"))


def check_default_accounts(users):
    risky = [u["Name"] for u in users if u["Enabled"] and
             u["Sid"].endswith(("-501", "-503", "-504"))]   # Guest, Default, WDAG
    builtin_admin = [u["Name"] for u in users if u["Enabled"] and
                     u["Sid"].endswith("-500")]             # built-in Administrator
    if risky:
        return finding("AC2-DEF", "AC-2(f)", "Default/guest accounts disabled",
                       "FAIL", "Enabled default accounts: " + ", ".join(risky))
    if builtin_admin:
        return finding("AC2-DEF", "AC-2(f)", "Default/guest accounts disabled",
                       "WARN", "Built-in Administrator (RID 500) is enabled: "
                       + ", ".join(builtin_admin) + ". Disable or rename it.")
    return finding("AC2-DEF", "AC-2(f)", "Default/guest accounts disabled",
                   "PASS", "Guest, DefaultAccount, WDAGUtilityAccount and built-in "
                   "Administrator are all disabled.")


def check_inactive(users, days, now):
    stale, never = [], []
    for u in users:
        if not u["Enabled"]:
            continue
        if u["LastLogonDt"] is None:
            never.append(u["Name"])
        elif (now - u["LastLogonDt"]).days > days:
            stale.append("%s (%d days)" % (u["Name"], (now - u["LastLogonDt"]).days))
    title = "Inactive accounts disabled (> %d days)" % days
    if stale:
        return finding("AC2-INACT", "AC-2(3)", title, "FAIL",
                       "Enabled but inactive: " + ", ".join(stale))
    if never:
        return finding("AC2-INACT", "AC-2(3)", title, "WARN",
                       "Enabled, never logged on: " + ", ".join(never))
    return finding("AC2-INACT", "AC-2(3)", title, "PASS",
                   "No enabled account exceeds the inactivity limit.")


def check_password_required(users):
    bad = [u["Name"] for u in users if u["Enabled"] and not u["PasswordRequired"]]
    if bad:
        return finding("AC2-PWREQ", "AC-2 / IA-5", "Enabled accounts require a password",
                       "FAIL", "No password required: " + ", ".join(bad))
    return finding("AC2-PWREQ", "AC-2 / IA-5", "Enabled accounts require a password",
                   "PASS", "All enabled accounts require a password.")


def check_password_expiry(users):
    bad = [u["Name"] for u in users if u["Enabled"] and not u["PasswordExpires"]]
    if bad:
        return finding("AC2-PWEXP", "AC-2 / IA-5", "Passwords have an expiry date",
                       "WARN", "Password never expires: " + ", ".join(bad))
    return finding("AC2-PWEXP", "AC-2 / IA-5", "Passwords have an expiry date",
                   "PASS", "All enabled accounts have password expiry.")


def check_admins(max_admins):
    members = get_admin_members()
    names = [m["Name"] for m in members]
    detail = "%d member(s): %s" % (len(names), ", ".join(names))
    if len(names) > max_admins:
        return finding("AC2-PRIV", "AC-2(7)", "Privileged group size (max %d)" % max_admins,
                       "WARN", detail + ". Review and remove unneeded admins.")
    return finding("AC2-PRIV", "AC-2(7)", "Privileged group size (max %d)" % max_admins,
                   "PASS", detail)


def check_audit_policy():
    """AC-2(4): account creation/modification/removal must generate audit records."""
    out = subprocess.run(["auditpol", "/get", "/category:Account Management", "/r"],
                         capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError("auditpol failed (run as Administrator): "
                           + (out.stderr.strip() or out.stdout.strip()))
    rows = csv.DictReader(io.StringIO(out.stdout.strip()))
    settings = {}
    for row in rows:
        guid = (row.get("Subcategory GUID") or "").upper()
        settings[guid] = row.get("Inclusion Setting", "")
    user_set = settings.get(GUID_USER_ACCT_MGMT, "unknown")
    group_set = settings.get(GUID_SEC_GROUP_MGMT, "unknown")
    detail = "User Account Mgmt: %s | Security Group Mgmt: %s" % (user_set, group_set)
    ok = "Success" in user_set and "Success" in group_set
    return finding("AC2-AUDIT", "AC-2(4)", "Account management auditing enabled",
                   "PASS" if ok else "FAIL", detail)


def check_inactivity_lock(max_secs):
    """AC-2(5): sessions should lock/log out after inactivity."""
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    title = "Inactivity lock <= %d seconds" % max_secs
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, _ = winreg.QueryValueEx(key, "InactivityTimeoutSecs")
    except FileNotFoundError:
        return finding("AC2-LOCK", "AC-2(5)", title, "FAIL",
                       "InactivityTimeoutSecs is not configured.")
    if 0 < value <= max_secs:
        return finding("AC2-LOCK", "AC-2(5)", title, "PASS",
                       "InactivityTimeoutSecs = %d" % value)
    return finding("AC2-LOCK", "AC-2(5)", title, "FAIL",
                   "InactivityTimeoutSecs = %d (must be 1-%d)" % (value, max_secs))


def safe_run(fid, control, name, func, *args):
    """Run a check; if it crashes, record an ERROR instead of stopping the scan."""
    try:
        return func(*args)
    except Exception as exc:
        return finding(fid, control, name, "ERROR", str(exc))


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def print_report(host, findings, users, now):
    print("=" * 78)
    print("NIST 800-53 AC-2 COMPLIANCE CHECK")
    print("Host: %s | Run: %s | Admin rights: %s"
          % (host, now.strftime("%Y-%m-%d %H:%M"), is_admin()))
    print("=" * 78)
    for f in findings:
        print("[%-5s] %-11s %s" % (f["status"], f["control"], f["check"]))
        print("         %s" % f["detail"])
    print("-" * 78)
    print("%-20s %-8s %-18s %s" % ("Account", "Enabled", "Last logon", "Idle days"))
    for u in users:
        last = u["LastLogonDt"]
        print("%-20s %-8s %-18s %s" % (
            u["Name"][:20], u["Enabled"],
            last.strftime("%Y-%m-%d %H:%M") if last else "never",
            (now - last).days if last else "-"))
    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in ("PASS", "FAIL", "WARN", "ERROR")}
    if counts["FAIL"]:
        verdict = "NON-COMPLIANT"
    elif counts["WARN"] or counts["ERROR"]:
        verdict = "REVIEW NEEDED"
    else:
        verdict = "COMPLIANT (technical checks)"
    print("-" * 78)
    print("PASS=%d FAIL=%d WARN=%d ERROR=%d  =>  %s"
          % (counts["PASS"], counts["FAIL"], counts["WARN"], counts["ERROR"], verdict))
    return verdict


def main():
    parser = argparse.ArgumentParser(description="NIST 800-53 AC-2 compliance check")
    parser.add_argument("--inactive-days", type=int, default=90)
    parser.add_argument("--max-admins", type=int, default=3)
    parser.add_argument("--max-idle-secs", type=int, default=900)
    parser.add_argument("--output", help="save findings to this JSON file")
    args = parser.parse_args()

    if platform.system() != "Windows":
        print("This version supports Windows only.")
        return 2

    now = datetime.now()
    host = socket.gethostname()
    if not is_admin():
        print("Warning: not running as Administrator; the audit check may fail.\n")

    try:
        users = get_local_users()
    except Exception as exc:
        print("Could not read local accounts: %s" % exc)
        return 2

    findings = [
        check_inventory(users),
        check_default_accounts(users),
        check_inactive(users, args.inactive_days, now),
        check_password_required(users),
        check_password_expiry(users),
        safe_run("AC2-PRIV", "AC-2(7)", "Privileged group size", check_admins, args.max_admins),
        safe_run("AC2-AUDIT", "AC-2(4)", "Account management auditing", check_audit_policy),
        safe_run("AC2-LOCK", "AC-2(5)", "Inactivity lock", check_inactivity_lock, args.max_idle_secs),
    ]
    verdict = print_report(host, findings, users, now)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"host": host, "run": now.isoformat(), "verdict": verdict,
                       "findings": findings}, fh, indent=2)
        print("Saved: " + args.output)
    return 1 if any(f["status"] == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())