#!/usr/bin/env python3
"""
ac2_final.py - Windows technical assessment helper for NIST SP 800-53 Rev. 5
control AC-2 (Account Management).

Scope: LOCAL Windows accounts and selected local settings only. This is an
assessment aid, not a certification of AC-2 compliance. Organizational
requirements (approvals, account managers, review frequency) need manual review.

Run from an Administrator prompt:
    python ac2_final.py
    python ac2_final.py --inactive-days 60 --output ac2-report.json

Exit codes: 0 = no FAIL findings, 1 = one or more FAIL findings,
            2 = unsupported OS or account list could not be collected
"""

import argparse
import csv
import ctypes
import io
import json
import platform
import shutil
import socket
import subprocess
import sys
from datetime import datetime

DATE_FMT = "%Y-%m-%dT%H:%M:%S"
ADMIN_GROUP_SID = "S-1-5-32-544"
GUID_USER_MGMT = "0CCE9235-69AE-11D9-BED3-505054503030"
GUID_GROUP_MGMT = "0CCE9237-69AE-11D9-BED3-505054503030"


# ---------------------------------------------------------------- helpers ---
def finding(fid, control, check, status, detail):
    """One result record. status: PASS, FAIL, REVIEW, INFO or ERROR."""
    return {"id": fid, "control": control, "check": check,
            "status": status, "detail": detail}


def is_admin():
    """True if running with an elevated Windows token."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_powershell(command, timeout=60):
    """Run a fixed PowerShell command; raise a readable error on failure."""
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise RuntimeError("PowerShell was not found.")
    result = subprocess.run(
        [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                           or "PowerShell command failed.")
    return result.stdout.strip()


def ps_json(command):
    """Run PowerShell, decode its JSON output, and always return a list."""
    output = run_powershell(command)
    if not output:
        return []
    data = json.loads(output)
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def parse_dt(text):
    """Convert 'yyyy-MM-ddTHH:mm:ss' text to a datetime (None if blank/bad)."""
    try:
        return datetime.strptime(text, DATE_FMT) if text else None
    except ValueError:
        return None


# ------------------------------------------------------- data collection ---
def get_local_users():
    def date_col(prop):
        return ("@{Name='%s';Expression={if($_.%s){$_.%s.ToString("
                "'yyyy-MM-ddTHH:mm:ss')}else{$null}}}" % (prop, prop, prop))
    command = ("$ErrorActionPreference='Stop'; Get-LocalUser | Select-Object "
               "Name, Enabled, PasswordRequired, "
               "@{Name='Sid';Expression={$_.SID.Value}}, %s, %s | "
               "ConvertTo-Json -Depth 3 -Compress"
               % (date_col("LastLogon"), date_col("AccountExpires")))
    users = ps_json(command)
    for u in users:
        u["LastLogonDt"] = parse_dt(u.get("LastLogon"))
        u["AccountExpiresDt"] = parse_dt(u.get("AccountExpires"))
    return users


def get_admin_members():
    command = ("$ErrorActionPreference='Stop'; Get-LocalGroupMember -SID '%s' | "
               "Select-Object Name, ObjectClass, PrincipalSource | "
               "ConvertTo-Json -Depth 3 -Compress" % ADMIN_GROUP_SID)
    return ps_json(command)


# ----------------------------------------------------------------- checks ---
def check_inventory(users):
    enabled = [u for u in users if u.get("Enabled") is True]
    names = ", ".join(sorted(u.get("Name", "<unknown>") for u in enabled)) or "none"
    return finding("AC2-INV", "AC-2(a),(f)", "Local account inventory", "INFO",
                   "%d local accounts: %d enabled, %d disabled. Enabled: %s. "
                   "Domain and application accounts are outside this inventory."
                   % (len(users), len(enabled), len(users) - len(enabled), names))


def check_default_accounts(users):
    title = "Review guest and default accounts"
    enabled = [u for u in users if u.get("Enabled") is True]
    risky = [u.get("Name", "<unknown>") for u in enabled
             if str(u.get("Sid", "")).endswith(("-501", "-503", "-504"))]
    admin500 = [u.get("Name", "<unknown>") for u in enabled
                if str(u.get("Sid", "")).endswith("-500")]
    if risky:
        return finding("AC2-DEFAULT", "AC-2(f)", title, "REVIEW",
                       "Enabled Guest/DefaultAccount/WDAG-style account(s): "
                       + ", ".join(risky) + ". Verify each is explicitly authorized.")
    if admin500:
        return finding("AC2-DEFAULT", "AC-2(f)", title, "REVIEW",
                       "Built-in Administrator (RID 500) is enabled: "
                       + ", ".join(admin500) + ". Verify its approved use.")
    return finding("AC2-DEFAULT", "AC-2(f)", title, "PASS",
                   "No enabled built-in Guest, DefaultAccount, WDAG or RID 500 account.")


def check_expired_inactive(users, days, now):
    expired, inactive, unknown = [], [], []
    for u in users:
        if u.get("Enabled") is not True:
            continue
        name = u.get("Name", "<unknown>")
        expiry, last = u.get("AccountExpiresDt"), u.get("LastLogonDt")
        if expiry and expiry <= now:
            expired.append(name)
        if last is None:
            unknown.append(name)
        elif (now - last).days >= days:
            inactive.append("%s (%d days)" % (name, (now - last).days))

    if expired:
        f1 = finding("AC2-EXPIRED", "AC-2(3)(a)", "Expired enabled accounts", "FAIL",
                     "Enabled but past expiration date: " + ", ".join(expired))
    else:
        f1 = finding("AC2-EXPIRED", "AC-2(3)(a)", "Expired enabled accounts", "PASS",
                     "No enabled account is past its expiration date.")

    title = "Accounts inactive for at least %d days" % days
    if inactive:
        f2 = finding("AC2-INACTIVE", "AC-2(3)(d)", title, "REVIEW",
                     "Potentially inactive: " + ", ".join(inactive)
                     + ". Disable per the organization's defined period.")
    elif unknown:
        f2 = finding("AC2-INACTIVE", "AC-2(3)(d)", title, "REVIEW",
                     "Last-logon data unavailable for: " + ", ".join(unknown))
    else:
        f2 = finding("AC2-INACTIVE", "AC-2(3)(d)", title, "PASS",
                     "No enabled account met the inactivity threshold.")
    return [f1, f2]


def check_password_required(users):
    title = "Local password-required setting"
    missing = [u.get("Name", "<unknown>") for u in users
               if u.get("Enabled") is True and u.get("PasswordRequired") is False]
    if missing:
        return finding("AC2-PWREQ", "Supporting (IA-5)", title, "REVIEW",
                       "PasswordRequired=False for: " + ", ".join(missing))
    return finding("AC2-PWREQ", "Supporting (IA-5)", title, "INFO",
                   "No enabled account has PasswordRequired=False.")


def check_privileged():
    members = get_admin_members()
    items = ["%s [%s; %s]" % (m.get("Name", "<unknown>"),
                              m.get("ObjectClass") or "unknown type",
                              m.get("PrincipalSource") or "unknown source")
             for m in members]
    return finding("AC2-PRIV", "AC-2(7)", "Privileged account inventory", "REVIEW",
                   "%d direct Administrators member(s): %s. Review each against "
                   "approved roles; nested groups need separate review."
                   % (len(members), "; ".join(items) or "none"))


def parse_audit(csv_text):
    """Turn `auditpol /r` CSV text into {subcategory GUID: inclusion setting}."""
    settings = {}
    for row in csv.DictReader(io.StringIO(csv_text.strip())):
        guid = (row.get("Subcategory GUID") or "").strip().strip("{}").upper()
        if guid:
            settings[guid] = (row.get("Inclusion Setting") or "").strip()
    return settings


def audit_finding(settings):
    user = settings.get(GUID_USER_MGMT, "Not reported")
    group = settings.get(GUID_GROUP_MGMT, "Not reported")
    ok = "Success" in user and "Success" in group
    return finding("AC2-AUDIT", "AC-2(4)", "Account-management success auditing",
                   "PASS" if ok else "FAIL",
                   "User Account Management: %s; Security Group Management: %s. "
                   "Verifies policy only, not retention or review." % (user, group))


def check_audit():
    result = subprocess.run(["auditpol", "/get", "/category:Account Management", "/r"],
                            capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                           or "auditpol failed (run as Administrator).")
    return audit_finding(parse_audit(result.stdout))


def manual_review():
    return [
        finding("AC2-GOVERNANCE", "AC-2(a)-(f),(h)-(l)", "Governance and authorization",
                "REVIEW", "Verify account types, account managers, approvals, "
                "authorized-user lists, notifications, shared-credential process "
                "and periodic account reviews."),
        finding("AC2-USE", "AC-2(g)", "Account-use monitoring", "REVIEW",
                "Verify account use is monitored and reviewed at the defined frequency."),
        finding("AC2-LOGOUT", "AC-2(5)", "Inactivity logout", "REVIEW",
                "Confirm the defined logout period and that users must log out. "
                "A screen-lock setting is addressed by AC-11, not AC-2(5)."),
    ]


# -------------------------------------------------------------- reporting ---
def summarize(findings):
    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in ("PASS", "FAIL", "REVIEW", "INFO", "ERROR")}
    if counts["FAIL"]:
        verdict = "FAILURES FOUND"
    elif counts["REVIEW"] or counts["ERROR"]:
        verdict = "MANUAL REVIEW REQUIRED"
    else:
        verdict = "NO TECHNICAL FAILURES FOUND"
    return counts, verdict


def print_report(host, os_name, now, findings, users, elevated):
    print("=" * 78)
    print("NIST SP 800-53 REV. 5 - AC-2 ACCOUNT MANAGEMENT ASSESSMENT")
    print("Host: %s | OS: %s" % (host, os_name))
    print("Run: %s | Administrator: %s" % (now.isoformat(timespec="seconds"), elevated))
    print("=" * 78)
    for f in findings:
        print("[%s] %s - %s" % (f["status"], f["control"], f["check"]))
        print("  " + f["detail"])
    print("-" * 78)
    print("%-24s %-8s %-18s %s" % ("Local account", "Enabled", "Last logon", "Idle days"))
    for u in sorted(users, key=lambda x: x.get("Name", "").lower()):
        last = u.get("LastLogonDt")
        print("%-24s %-8s %-18s %s" % (
            u.get("Name", "<unknown>")[:24], u.get("Enabled"),
            last.strftime("%Y-%m-%d %H:%M") if last else "unavailable",
            (now - last).days if last else "-"))
    counts, verdict = summarize(findings)
    print("-" * 78)
    print("PASS=%(PASS)d FAIL=%(FAIL)d REVIEW=%(REVIEW)d INFO=%(INFO)d "
          "ERROR=%(ERROR)d" % counts + " => " + verdict)
    print("This result is not a formal determination of overall AC-2 compliance.")
    return verdict


def main():
    parser = argparse.ArgumentParser(description="NIST 800-53 Rev. 5 AC-2 check")
    parser.add_argument("--inactive-days", type=int, default=90)
    parser.add_argument("--output", help="optional JSON report path")
    args = parser.parse_args()

    if platform.system() != "Windows":
        print("ERROR: This script supports Windows only.", file=sys.stderr)
        return 2
    if args.inactive_days < 1:
        parser.error("--inactive-days must be at least 1")

    now, host = datetime.now(), socket.gethostname()
    os_name, elevated = platform.platform(), is_admin()
    if not elevated:
        print("WARNING: Not Administrator; some checks may be incomplete.\n")

    try:
        users = get_local_users()
    except Exception as exc:
        print("ERROR: Could not collect local accounts: %s" % exc, file=sys.stderr)
        return 2

    findings = [check_inventory(users), check_default_accounts(users),
                *check_expired_inactive(users, args.inactive_days, now),
                check_password_required(users), *manual_review()]
    for fid, control, name, func in (
            ("AC2-PRIV", "AC-2(7)", "Privileged account inventory", check_privileged),
            ("AC2-AUDIT", "AC-2(4)", "Account-management auditing", check_audit)):
        try:
            findings.append(func())
        except Exception as exc:       # one failed check must not stop the scan
            findings.append(finding(fid, control, name, "ERROR", str(exc)))

    verdict = print_report(host, os_name, now, findings, users, elevated)

    if args.output:
        report = {"standard": "NIST SP 800-53 Rev. 5", "control": "AC-2",
                  "host": host, "run_time": now.isoformat(timespec="seconds"),
                  "verdict": verdict, "findings": findings,
                  "accounts": [{k: v for k, v in u.items()
                                if k not in ("LastLogonDt", "AccountExpiresDt")}
                               for u in users]}
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, default=str)
            print("JSON report saved to: " + args.output)
        except OSError as exc:
            print("ERROR: Could not write report: %s" % exc, file=sys.stderr)
            return 2

    return 1 if any(f["status"] == "FAIL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())