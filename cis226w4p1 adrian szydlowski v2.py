# -*- coding: utf-8 -*-
"""
Created on Thu Nov 12 23:10:55 2026

@author: adrian szydlowski
"""

#!/usr/bin/env python3
"""sys_inventory_final.py - System inventory script (standard library only).

Collects:
  1. OS information
  2. Installed hotfix records (Windows) or a patch baseline (Linux/macOS)
  3. Local listening TCP ports with PID and process name
  4. Findings: exposed risky ports and a stale-patch warning

Every section reports a status, so "nothing found" can be told apart from
"the command failed".

Run:   python sys_inventory_final.py            (human-readable report)
       python sys_inventory_final.py --json     (JSON output)
       python sys_inventory_final.py --selftest (run built-in tests)

Exit codes: 0 = all sections collected, 2 = a section could not be collected,
            1 = a self-test failed (also under python -O).
"""
import argparse
import csv
import io
import ipaddress
import json
import platform
import re
import subprocess  # nosec B404 - needed to query OS tools; always argument lists, never a shell
import sys
from datetime import date, datetime

TIMEOUT = 30           # seconds; a hung child process cannot freeze the script
HOTFIX_TIMEOUT = 120   # Get-HotFix is slow on some machines
STALE_DAYS = 90        # warn if the newest Windows hotfix is older than this
KB_PATTERN = re.compile(r"KB\d{6,8}")
PORT_PATTERN = re.compile(r"[0-9]{1,5}")   # ASCII digits only
PID_PATTERN = re.compile(r"[0-9]+")
# Control characters, C1 controls, and Unicode line/bidi-override characters.
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
SS_PROC = re.compile(r'\(\("([^"]+)",pid=(\d+)')

RISKY_PORTS = {
    21: "FTP (cleartext)",
    23: "Telnet (cleartext)",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}


# ---------------------------------------------------------------- helpers
def run_cmd(args, ok_codes=(0,), timeout=TIMEOUT):
    """Run a command as an argument list (never shell=True).
    Returns (ok, stdout, error_message) so callers can tell failure from empty."""
    try:
        r = subprocess.run(  # nosec B603 - args are fixed lists from this file, shell=False
            args, capture_output=True, text=True, timeout=timeout, check=False,
            errors="replace",  # non-UTF-8 output (e.g. Windows code pages) must not crash us
        )
    except FileNotFoundError:
        return False, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"timed out after {timeout}s: {args[0]}"
    except OSError as exc:
        return False, "", f"could not run {args[0]}: {exc}"
    if r.returncode not in ok_codes:
        return False, r.stdout, r.stderr.strip() or f"exit code {r.returncode}"
    return True, r.stdout, ""


def sanitize(text):
    """Replace control and bidi-override characters so external data cannot inject
    terminal escape sequences or spoof the report. Normal non-ASCII text
    (accented names, other scripts) is preserved."""
    return CONTROL_CHARS.sub("?", str(text))


def section(status, note="", **data):
    return {"status": status, "note": note, **data}


# ---------------------------------------------------------------- OS info
def get_os_info():
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "collected_at": datetime.now().isoformat(timespec="seconds"),
    }
    if info["system"] == "Linux":
        try:
            info["distro"] = platform.freedesktop_os_release().get("PRETTY_NAME", "")
        except (OSError, AttributeError):
            pass
    return info


# ---------------------------------------------------------------- Patches
def get_patches():
    system = platform.system()
    if system == "Windows":
        ps = (
            "Get-HotFix | Select-Object HotFixID,Description,"
            "@{n='InstalledOn';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}"
            " | ConvertTo-Json -Compress"
        )
        ok, out, err = run_cmd(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=HOTFIX_TIMEOUT,
        )
        if not ok:
            return section("error", err, hotfixes=[], days_since_latest=None)
        hotfixes = parse_hotfix_json(out.strip())
        return section(
            "ok" if hotfixes else "empty",
            "" if hotfixes else "Get-HotFix ran but returned no valid records.",
            hotfixes=hotfixes,
            days_since_latest=days_since_latest(hotfixes),
        )
    # Linux/macOS have no hotfix records. Report a clearly labelled baseline
    # instead of pretending it is a hotfix list.
    baseline = {"kernel_or_release": platform.release()}
    if system == "Darwin":
        baseline["macos_version"] = platform.mac_ver()[0]
    return section(
        "not_applicable",
        "Hotfix records are Windows-only; showing OS baseline instead.",
        hotfixes=[],
        days_since_latest=None,
        baseline=baseline,
    )


def parse_hotfix_json(text):
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):  # PowerShell returns a bare object for 1 result
        data = [data]
    if not isinstance(data, list):
        return []
    clean = []
    for item in data:
        if not isinstance(item, dict):  # ignore strings, numbers, nulls
            continue
        kb = item.get("HotFixID")
        if not isinstance(kb, str) or not KB_PATTERN.fullmatch(kb):
            continue
        desc = item.get("Description")
        installed = item.get("InstalledOn")
        clean.append(
            {
                "HotFixID": kb,
                "Description": sanitize(desc) if isinstance(desc, str) else "",
                "InstalledOn": sanitize(installed) if isinstance(installed, str) else "",
            }
        )
    return clean


def days_since_latest(hotfixes, today=None):
    dates = []
    for h in hotfixes:
        try:
            dates.append(datetime.strptime(h["InstalledOn"], "%Y-%m-%d").date())
        except ValueError:
            continue
    if not dates:
        return None
    return ((today or date.today()) - max(dates)).days


# ---------------------------------------------------------------- Ports
def split_addr(addr):
    """Split 'host:port', '[v6]:port', 'host%scope:port' or '*:port'
    into (host, int port). Returns None if malformed."""
    host, sep, port = addr.rpartition(":")
    if not sep or not PORT_PATTERN.fullmatch(port):
        return None
    p = int(port)
    if not 0 < p < 65536:
        return None
    host = host.strip("[]").split("%", 1)[0]  # drop interface scope (%lo, %4)
    return host, p


def is_loopback(host):
    """True only for loopback. Wildcards and unparseable hosts count as exposed
    (fail-safe: when unsure, report it)."""
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback too
    return ip.is_loopback


def _entry(host, port, pid="", process=""):
    return {"address": host, "port": port, "pid": pid, "process": process}


def _sorted(ports):
    return sorted(ports, key=lambda x: (x["port"], x["address"]))


def parse_tasklist_csv(text):
    """Map PID -> process name from `tasklist /FO CSV /NH`."""
    names = {}
    try:
        for row in csv.reader(io.StringIO(text, newline="")):
            if len(row) >= 2 and PID_PATTERN.fullmatch(row[1]):
                names[row[1]] = sanitize(row[0])
    except csv.Error:  # stray newline/NUL in malformed output: keep what we parsed
        pass
    return names


def parse_netstat_windows(text, names=None):
    names = names or {}
    ports = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            addr = split_addr(parts[1])
            if addr and PID_PATTERN.fullmatch(parts[4]):
                ports.append(_entry(addr[0], addr[1], parts[4], names.get(parts[4], "")))
    return _sorted(ports)


def parse_ss_linux(text):
    ports = []
    for line in text.splitlines():
        parts = line.split()
        # State Recv-Q Send-Q Local Peer [Process]  (a header row is skipped)
        if len(parts) >= 4 and parts[0].upper() == "LISTEN":
            addr = split_addr(parts[3])
            if addr:
                m = SS_PROC.search(line)
                ports.append(_entry(addr[0], addr[1],
                                    m.group(2) if m else "",
                                    sanitize(m.group(1)) if m else ""))
    return _sorted(ports)


def parse_lsof_mac(text):
    ports = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 10 and parts[-1] == "(LISTEN)":
            addr = split_addr(parts[8])
            if addr and PID_PATTERN.fullmatch(parts[1]):
                ports.append(_entry(addr[0], addr[1], parts[1], sanitize(parts[0])))
    return _sorted(ports)


def get_listening_ports():
    system = platform.system()
    if system == "Windows":
        # No "-p TCP": that switch shows IPv4 only. Plain -ano lists IPv4 and
        # IPv6 TCP rows (both labelled TCP) plus UDP rows, which the parser skips.
        ok, out, err = run_cmd(["netstat", "-ano"])
        if not ok:
            return section("error", err, ports=[])
        # Process names are a bonus; failure here does not fail the section.
        t_ok, t_out, _ = run_cmd(["tasklist", "/FO", "CSV", "/NH"])
        ports = parse_netstat_windows(out, parse_tasklist_csv(t_out) if t_ok else {})
    elif system == "Linux":
        ok, out, err = run_cmd(["ss", "-ltnp"])
        if not ok:
            return section("error", err, ports=[])
        ports = parse_ss_linux(out)
    elif system == "Darwin":
        # lsof exits 1 when nothing matches, which is not an error for us
        ok, out, err = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], ok_codes=(0, 1))
        if not ok:
            return section("error", err, ports=[])
        ports = parse_lsof_mac(out)
    else:
        return section("error", f"unsupported OS: {system}", ports=[])
    return section("ok" if ports else "empty",
                   "" if ports else "Command succeeded; no listening TCP ports.",
                   ports=ports)


# ---------------------------------------------------------------- Findings
def flag_risky(ports):
    findings = []
    for p in ports:
        if p["port"] in RISKY_PORTS and not is_loopback(p["address"]):
            findings.append({**p, "reason": RISKY_PORTS[p["port"]]})
    return findings


def build_report():
    patches = get_patches()
    ports = get_listening_ports()
    stale = patches.get("days_since_latest")
    return {
        "os": get_os_info(),
        "patches": patches,
        "listening_tcp": ports,
        "findings": {
            "exposed_risky_ports": flag_risky(ports["ports"]),
            "stale_patches": stale is not None and stale > STALE_DAYS,
        },
    }


def exit_code(report):
    failed = any(report[k]["status"] == "error" for k in ("patches", "listening_tcp"))
    return 2 if failed else 0


# ---------------------------------------------------------------- Output
def print_report(r):
    print("=== OS INFORMATION ===")
    for k, v in r["os"].items():
        print(f"{k:>13}: {sanitize(v)}")

    pt = r["patches"]
    print("\n=== HOTFIXES / PATCH BASELINE ===")
    if pt["status"] == "error":
        print(f"[ERROR] Could not collect: {sanitize(pt['note'])}")
    else:
        if pt["note"]:
            print(pt["note"])
        for k, v in pt.get("baseline", {}).items():
            print(f"{k:>18}: {sanitize(v)}")
        for h in pt["hotfixes"]:
            print(f"{h['HotFixID']:<12} {h['InstalledOn']:<12} {h['Description']}")
        if r["findings"]["stale_patches"]:
            print(f"[!] Newest hotfix is {pt['days_since_latest']} days old "
                  f"(threshold {STALE_DAYS}).")

    lp = r["listening_tcp"]
    print("\n=== LISTENING TCP PORTS ===")
    if lp["status"] == "error":
        print(f"[ERROR] Could not collect: {sanitize(lp['note'])}")
    else:
        if lp["note"]:
            print(lp["note"])
        for p in lp["ports"]:
            who = f"{p['process']} " if p["process"] else ""
            print(f"{p['address']:<40} {p['port']:<6} {who}PID {p['pid'] or 'n/a'}")
        if any(not p["pid"] for p in lp["ports"]):
            print("Note: PID/process is blank for sockets owned by other users; "
                  "run as administrator/root to see them.")

    print("\n=== FINDINGS ===")
    risky = r["findings"]["exposed_risky_ports"]
    if risky:
        for p in risky:
            print(f"[!] Port {p['port']} on {p['address']} "
                  f"(PID {p['pid'] or 'n/a'}): {p['reason']}")
    else:
        print("No exposed risky ports detected.")
    print("Note: these are leads to investigate, not confirmed vulnerabilities.")


# ---------------------------------------------------------------- Self-test
_checks_run = 0


def check(condition, message=""):
    """Explicit replacement for `assert`. Python strips assert statements under
    -O / -OO, which would let --selftest report success without checking anything;
    this raises AssertionError no matter how the interpreter is run."""
    global _checks_run
    _checks_run += 1
    if not condition:
        raise AssertionError(f"self-test failed: {message}")
def selftest():
    from contextlib import redirect_stdout
    from unittest import mock

    # --- Windows netstat + tasklist (IPv4 and IPv6 rows, UDP, bad port)
    win = (
        "Active Connections\n\n"
        "  Proto  Local Address          Foreign Address        State           PID\n"
        "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1032\n"
        "  TCP    [::]:445               [::]:0                 LISTENING       4\n"
        "  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       999\n"
        "  TCP    10.0.0.5:51000         1.2.3.4:443            ESTABLISHED     777\n"
        "  TCP    0.0.0.0:99999          0.0.0.0:0              LISTENING       5\n"
        "  UDP    0.0.0.0:5353           *:*                                    1032\n"
    )
    names = parse_tasklist_csv('"svchost.exe","1032","Services","0","9,000 K"\n"System","4","Services","0","10 K"\n')
    check(names == {"1032": "svchost.exe", "4": "System"}, names)
    parse_tasklist_csv('"a","1"\r"b","2"\x00')       # malformed CSV must not raise
    r = parse_netstat_windows(win, names)
    check([p["port"] for p in r] == [135, 445, 8080], r)      # bad port + UDP dropped
    check(r[0]["process"] == "svchost.exe" and r[1]["address"] == "::", 'r[0]["process"] == "svchost.exe" and r[1]["address"] == "::"')
    check(parse_netstat_windows("tcp 0.0.0.0:80 0.0.0.0:0 listening 4")[0]["port"] == 80, 'parse_netstat_windows("tcp 0.0.0.0:80 0.0.0.0:0 listening 4")[0]["port"] == 80')
    check(parse_netstat_windows("") == [], 'parse_netstat_windows("") == []')

    # --- Linux ss, including header, scope id, wildcard and process info
    ss = (
        "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))\n'
        "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n"
        "LISTEN 0 128 [::]:22 [::]:*\n"
        "LISTEN 0 128 *:8080 *:*\n"
    )
    s = parse_ss_linux(ss)
    check([p["port"] for p in s] == [22, 22, 53, 8080], s)
    check(s[0]["process"] == "sshd" and s[0]["pid"] == "812", 's[0]["process"] == "sshd" and s[0]["pid"] == "812"')
    check([p for p in s if p["port"] == 53][0]["address"] == "127.0.0.53", '[p for p in s if p["port"] == 53][0]["address"] == "127.0.0.53"')
    check(parse_ss_linux("") == [], 'parse_ss_linux("") == []')

    # --- macOS lsof
    lsof = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "ControlCe 612 ski 7u IPv4 0x1 0t0 TCP *:7000 (LISTEN)\n"
    )
    m = parse_lsof_mac(lsof)
    check(m[0]["port"] == 7000 and m[0]["address"] == "*" and m[0]["pid"] == "612", 'm[0]["port"] == 7000 and m[0]["address"] == "*" and m[0]["pid"] == "612"')
    check(parse_lsof_mac("") == [], 'parse_lsof_mac("") == []')

    # --- address handling edge cases
    check(split_addr("1.2.3.4:0") is None, 'split_addr("1.2.3.4:0") is None')
    check(split_addr("1.2.3.4:65536") is None, 'split_addr("1.2.3.4:65536") is None')
    check(split_addr("1.2.3.4:\u00b2") is None, 'split_addr("1.2.3.4:\\u00b2") is None')      # unicode digit rejected
    check(split_addr("no-port") is None, 'split_addr("no-port") is None')
    check(split_addr("[fe80::1%4]:135") == ("fe80::1", 135), 'split_addr("[fe80::1%4]:135") == ("fe80::1", 135)')

    # --- loopback classification
    for h in ("127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1", "localhost"):
        check(is_loopback(h), h)
    for h in ("0.0.0.0", "::", "*", "10.0.0.5", "not-an-ip", ""):  # nosec B104 - test data, not a bind
        check(not is_loopback(h), h)

    # --- hotfix parsing
    one = '{"HotFixID":"KB5030211","Description":"Update","InstalledOn":"2023-09-20"}'
    check(parse_hotfix_json(one)[0]["HotFixID"] == "KB5030211", 'parse_hotfix_json(one)[0]["HotFixID"] == "KB5030211"')
    check(parse_hotfix_json('[{"HotFixID":"bad; rm -rf"}]') == [], 'parse_hotfix_json(\'[{"HotFixID":"bad; rm -rf"}]\') == []')
    mixed = parse_hotfix_json('["KB1234567", 5, null, {"HotFixID":"KB1234567"}]')
    check(len(mixed) == 1 and mixed[0]["HotFixID"] == "KB1234567", 'len(mixed) == 1 and mixed[0]["HotFixID"] == "KB1234567"')
    check(parse_hotfix_json("5") == [] and parse_hotfix_json("not json") == [], 'parse_hotfix_json("5") == [] and parse_hotfix_json("not json") == []')
    check(parse_hotfix_json("") == [], 'parse_hotfix_json("") == []')

    # --- stale-patch calculation
    hf = [{"HotFixID": "KB1234567", "Description": "", "InstalledOn": "2026-01-01"},
          {"HotFixID": "KB7654321", "Description": "", "InstalledOn": "2026-02-01"}]
    check(days_since_latest(hf, today=date(2026, 3, 3)) == 30, 'days_since_latest(hf, today=date(2026, 3, 3)) == 30')
    check(days_since_latest([]) is None, 'days_since_latest([]) is None')

    # --- risky-port flagging
    check([f["port"] for f in flag_risky(r)] == [135, 445], '[f["port"] for f in flag_risky(r)] == [135, 445]')   # 8080 not risky
    check(flag_risky(_sorted([_entry("::ffff:127.0.0.1", 3389)])) == [], 'flag_risky(_sorted([_entry("::ffff:127.0.0.1", 3389)])) == []')

    # --- sanitizer: strips controls, keeps normal non-ASCII text
    check(sanitize("ok\x1b[31mred") == "ok?[31mred", 'sanitize("ok\\x1b[31mred") == "ok?[31mred"')
    check(sanitize("a\u202eb") == "a?b", 'sanitize("a\\u202eb") == "a?b"')
    check(sanitize("Zo\u00eb \u4e2d\u6587") == "Zo\u00eb \u4e2d\u6587", 'sanitize("Zo\\u00eb \\u4e2d\\u6587") == "Zo\\u00eb \\u4e2d\\u6587"')

    # --- run_cmd failure modes
    ok, _, err = run_cmd(["definitely-not-a-real-command-xyz"])
    check(not ok and "not found" in err, 'not ok and "not found" in err')
    ok, out, _ = run_cmd([sys.executable, "-c",
                          "import sys; sys.stdout.buffer.write(b'caf\\xe9')"])
    check(ok and out.startswith("caf"), 'ok and out.startswith("caf")')        # invalid UTF-8 is replaced, not fatal
    ok, _, err = run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    check(not ok and "timed out" in err, 'not ok and "timed out" in err')
    ok, _, err = run_cmd([sys.executable, "-c", "import sys; sys.exit(3)"])
    check(not ok and "exit code 3" in err, 'not ok and "exit code 3" in err')
    check(run_cmd([sys.executable, "-c", "import sys; sys.exit(1)"], ok_codes=(0, 1))[0], 'run_cmd([sys.executable, "-c", "import sys; sys.exit(1)"], ok_codes=(0, 1))[0]')

    # --- end-to-end with simulated OS commands (exercises the whole pipeline)
    this = sys.modules[__name__]

    def simulate(system, outputs):
        def fake_run(args, ok_codes=(0,), timeout=TIMEOUT):
            return outputs.get(args[0], (False, "", f"command not found: {args[0]}"))
        with mock.patch.object(platform, "system", return_value=system), \
             mock.patch.object(this, "run_cmd", fake_run):
            report = build_report()
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_report(report)
            json.dumps(report)                 # must be JSON-serialisable
        return report, buf.getvalue()

    old = '[{"HotFixID":"KB5030211","Description":"Update","InstalledOn":"2020-01-01"}]'
    rep, text = simulate("Windows", {
        "netstat": (True, win, ""), "tasklist": (True, '"System","4"\n', ""),
        "powershell": (True, old, "")})
    check(rep["findings"]["stale_patches"] and exit_code(rep) == 0, 'rep["findings"]["stale_patches"] and exit_code(rep) == 0')
    check([p["port"] for p in rep["findings"]["exposed_risky_ports"]] == [135, 445], '[p["port"] for p in rep["findings"]["exposed_risky_ports"]] == [135, 445]')
    check("[!] Port 445" in text and "days old" in text, '"[!] Port 445" in text and "days old" in text')

    rep, text = simulate("Windows", {"netstat": (False, "", "boom"),
                                     "powershell": (False, "", "denied")})
    check(exit_code(rep) == 2 and "[ERROR]" in text, 'exit_code(rep) == 2 and "[ERROR]" in text')

    rep, text = simulate("Linux", {"ss": (True, ss, "")})
    check(exit_code(rep) == 0 and rep["patches"]["status"] == "not_applicable", 'exit_code(rep) == 0 and rep["patches"]["status"] == "not_applicable"')
    check("run as administrator/root" in text, '"run as administrator/root" in text')      # blank-PID note shown

    rep, text = simulate("Linux", {})               # ss missing
    check(exit_code(rep) == 2 and "command not found: ss" in text, 'exit_code(rep) == 2 and "command not found: ss" in text')

    rep, _ = simulate("Darwin", {"lsof": (True, lsof, "")})
    check(rep["listening_tcp"]["ports"][0]["port"] == 7000, 'rep["listening_tcp"]["ports"][0]["port"] == 7000')
    rep, _ = simulate("Darwin", {"lsof": (True, "", "")})
    check(rep["listening_tcp"]["status"] == "empty", 'rep["listening_tcp"]["status"] == "empty"')
    rep, _ = simulate("Plan9", {})
    check(rep["listening_tcp"]["status"] == "error", 'rep["listening_tcp"]["status"] == "error"')

    print(f"All self-tests passed ({_checks_run} checks).")


def main():
    ap = argparse.ArgumentParser(description="System inventory (no external scanner).")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--selftest", action="store_true", help="run built-in tests")
    args = ap.parse_args()
    # Windows consoles may not encode every character; never crash on print.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if args.selftest:
        try:
            selftest()
        except AssertionError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())