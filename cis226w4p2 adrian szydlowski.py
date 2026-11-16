# -*- coding: utf-8 -*-
"""
Created on Sun Nov 15 19:20:04 2026

@author: adrian szydlowski
"""

"""
Vulnerability Scan Results Analyzer (v2)
----------------------------------------
Reads three inventory files (CSV or JSON), derives security findings from them
without any external scanner, scores each finding, and writes a prioritized
remediation list plus a per-host risk summary.

Inputs  : os_inventory, installed_hotfixes, listening_ports  (.csv or .json)
Outputs : prioritized_remediation_list.csv, host_risk_summary.csv
Usage   : python vuln_analyzer.py [--inventory F] [--hotfixes F] [--ports F]
                                  [--outdir DIR] [--as-of YYYY-MM-DD]
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------
# CONFIGURATION (all scoring rules live here so they are easy to audit)
# --------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {".csv", ".json"}

REQUIRED_COLUMNS = {
    "inventory": {"Host", "OS_Name", "OS_Build", "Asset_Criticality"},
    "hotfixes": {"Host", "HotFixID", "InstalledOn"},
    "ports": {"Host", "LocalPort", "Service", "Exposure"},
}

# Asset criticality multiplies the base score of every finding on that host.
CRITICALITY_MULTIPLIER = {"Critical": 1.5, "High": 1.25, "Medium": 1.0, "Low": 0.75}

# Last day Microsoft supplies security updates, keyed by (OS name, build).
# Verify against https://learn.microsoft.com/lifecycle before relying on it.
OS_END_OF_SUPPORT = {
    ("Windows Server 2012 R2", 9600): "2023-10-10",
    ("Windows Server 2016", 14393): "2027-01-12",
    ("Windows Server 2019", 17763): "2029-01-09",
    ("Windows Server 2022", 20348): "2031-10-14",
    ("Windows 10 Enterprise", 19045): "2025-10-14",
    ("Windows 10 Pro", 19045): "2025-10-14",
    ("Windows 11 Pro", 26100): "2026-10-13",          # 24H2 Home/Pro
    ("Windows 11 Enterprise", 26100): "2027-10-12",   # 24H2 Enterprise/Edu
}

# Risky listening services: (port, exposure) -> (base score 0-10, why it matters)
PORT_RULES = {
    (23, "Network"): (9.0, "Telnet sends credentials in clear text"),
    (445, "Network"): (8.5, "SMB reachable from the network (ransomware/worm path)"),
    (5900, "Network"): (8.0, "VNC remote control exposed to the network"),
    (21, "Network"): (7.5, "FTP sends credentials in clear text"),
    (3389, "Network"): (7.0, "RDP exposed to the network (brute force target)"),
    (1433, "Network"): (6.5, "SQL Server port exposed beyond the host"),
    (80, "Network"): (3.0, "Unencrypted HTTP service"),
    (8080, "Internal"): (3.0, "Unexpected alternate HTTP service (dev server?)"),
    (3389, "Internal"): (2.0, "RDP enabled (internal only)"),
}

# Patch age thresholds in days: (minimum age, base score), checked oldest first
PATCH_AGE_RULES = [(365, 8.0), (180, 6.5), (90, 5.0)]
NO_PATCH_SCORE = 8.0
UNSUPPORTED_OS_SCORE = 9.0
EOL_SOON_SCORE = 5.0
EOL_SOON_DAYS = 90

# Priority tiers by final score: lower bound -> (label, target time to fix)
TIERS = [(10.0, "P1 - Critical", "Fix within 24-72 hours"),
         (8.0, "P2 - High", "Fix within 7 days"),
         (5.0, "P3 - Medium", "Fix within 30 days"),
         (-np.inf, "P4 - Low", "Fix in next maintenance window")]

ACTIONS = {
    "Unsupported OS": "Upgrade or replace the OS, or isolate the host until it is upgraded",
    "OS support ending soon": "Plan an OS upgrade before support ends",
    "Missing patches": "Run Windows Update and install the latest cumulative/security updates",
    "No patch history": "Verify the host is reporting; install all current updates",
    "Risky service": "Disable the service or restrict it with a firewall rule; use an encrypted alternative",
}

FINDING_COLS = ["Host", "Finding_Type", "Detail", "Base_Score"]


class AnalyzerError(Exception):
    """Raised for bad input that the user can fix (shown without a traceback)."""


# --------------------------------------------------------------------------
# 1. LOADING, VALIDATION AND CLEANING
# --------------------------------------------------------------------------
def load_file(path: str, name: str) -> pd.DataFrame:
    """Load a CSV or JSON file and verify the columns we depend on exist."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise AnalyzerError(f"{path}: unsupported file type '{ext}' (use .csv or .json)")
    if not os.path.isfile(path):
        raise AnalyzerError(f"{path}: file not found")
    try:
        # utf-8-sig strips the invisible byte-order mark Excel adds to CSV files
        df = pd.read_csv(path, encoding="utf-8-sig") if ext == ".csv" else pd.read_json(path)
    except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as e:
        raise AnalyzerError(f"{path}: could not be parsed ({e})") from e
    df.columns = [str(c).strip() for c in df.columns]
    missing = REQUIRED_COLUMNS[name] - set(df.columns)
    if missing:
        raise AnalyzerError(f"{path}: missing required column(s): {sorted(missing)}")
    return df


def clean_text(df: pd.DataFrame, cols, upper=(), title=()) -> pd.DataFrame:
    """Trim whitespace; upper-case hostnames; title-case labels (so 'high' == 'High')."""
    df = df.copy()
    for c in cols:
        s = df[c].astype("string").str.strip()
        if c in upper:
            s = s.str.upper()
        if c in title:
            s = s.str.title()
        df[c] = s
    return df


# --------------------------------------------------------------------------
# 2. FINDING GENERATORS (vectorized: no row-by-row Python loops over big data)
# --------------------------------------------------------------------------
def os_findings(inv: pd.DataFrame, as_of: pd.Timestamp) -> pd.DataFrame:
    eol = pd.DataFrame([(n, b, pd.Timestamp(d)) for (n, b), d in OS_END_OF_SUPPORT.items()],
                       columns=["OS_Name", "OS_Build", "EOL"])
    m = inv.merge(eol, on=["OS_Name", "OS_Build"], how="inner")
    m["days"] = (as_of - m["EOL"]).dt.days
    ended, soon = m["days"] > 0, (m["days"] <= 0) & (m["days"] > -EOL_SOON_DAYS)
    m = m[ended | soon].copy()
    ended = m["days"] > 0
    m["Finding_Type"] = np.where(ended, "Unsupported OS", "OS support ending soon")
    m["Base_Score"] = np.where(ended, UNSUPPORTED_OS_SCORE, EOL_SOON_SCORE)
    m["Detail"] = [
        f"{n} (build {b}) support ended {e.date()} ({d} days ago)" if d > 0
        else f"{n} (build {b}) support ends {e.date()} (in {-d} days)"
        for n, b, e, d in zip(m["OS_Name"], m["OS_Build"], m["EOL"], m["days"])]
    return m[FINDING_COLS]


def patch_findings(inv: pd.DataFrame, hf: pd.DataFrame, as_of: pd.Timestamp) -> pd.DataFrame:
    hf = hf.copy()
    hf["InstalledOn"] = pd.to_datetime(hf["InstalledOn"], errors="coerce")  # bad dates -> NaT
    latest = hf.groupby("Host", as_index=False)["InstalledOn"].max().rename(columns={"InstalledOn": "Last"})
    # a left merge (instead of .map) also works when the hotfix file is empty
    p = pd.DataFrame({"Host": inv["Host"].to_numpy()}).merge(latest, on="Host", how="left")
    p["Last"] = pd.to_datetime(p["Last"])
    p["age"] = (as_of - p["Last"]).dt.days
    # np.select picks the first matching condition, so thresholds go oldest first
    conds = [p["Last"].isna()] + [p["age"] >= a for a, _ in PATCH_AGE_RULES]
    scores = [NO_PATCH_SCORE] + [s for _, s in PATCH_AGE_RULES]
    p["Base_Score"] = np.select(conds, scores, default=0.0)
    p = p[p["Base_Score"] > 0].copy()
    none = p["Last"].isna()
    p["Finding_Type"] = np.where(none, "No patch history", "Missing patches")
    p["Detail"] = [
        "No valid hotfix records found" if pd.isna(l)
        else f"Last update installed {l.date()} ({int(a)} days ago)"
        for l, a in zip(p["Last"], p["age"])]
    return p[FINDING_COLS]


def port_findings(ports: pd.DataFrame) -> pd.DataFrame:
    rules = pd.DataFrame([(p, e, s, w) for (p, e), (s, w) in PORT_RULES.items()],
                         columns=["LocalPort", "Exposure", "Base_Score", "Why"])
    p = ports.copy()
    p["LocalPort"] = pd.to_numeric(p["LocalPort"], errors="coerce")
    p = p.dropna(subset=["LocalPort"]).astype({"LocalPort": "int64"})
    p = p.drop_duplicates(subset=["Host", "LocalPort", "Exposure"])   # same listener twice = one finding
    m = p.merge(rules, on=["LocalPort", "Exposure"], how="inner")
    m["Finding_Type"] = "Risky service"
    m["Detail"] = (m["Service"].astype(str) + " on port " + m["LocalPort"].astype(str)
                   + " (" + m["Exposure"].astype(str) + "): " + m["Why"])
    return m[FINDING_COLS]


# --------------------------------------------------------------------------
# 3. SCORING, RANKING AND OUTPUT
# --------------------------------------------------------------------------
def build_plan(findings: pd.DataFrame, inv: pd.DataFrame) -> pd.DataFrame:
    if findings.empty:
        return findings
    cols = ["Host", "IP_Address", "Asset_Type", "Asset_Criticality", "Owner"]
    df = findings.merge(inv[[c for c in cols if c in inv.columns]], on="Host", how="left")
    df["Multiplier"] = df["Asset_Criticality"].map(CRITICALITY_MULTIPLIER).fillna(1.0)
    df["Priority_Score"] = (df["Base_Score"] * df["Multiplier"]).round(2)
    bins = [t[0] for t in reversed(TIERS)] + [np.inf]
    idx = pd.cut(df["Priority_Score"], bins=bins, right=False, labels=False)  # 0 = lowest tier
    labels = [t[1] for t in reversed(TIERS)]
    slas = [t[2] for t in reversed(TIERS)]
    df["Priority"] = idx.map(dict(enumerate(labels)))
    df["Target"] = idx.map(dict(enumerate(slas)))
    df["Recommended_Action"] = df["Finding_Type"].map(ACTIONS)
    df = df.sort_values(["Priority_Score", "Host", "Finding_Type"],
                        ascending=[False, True, True]).reset_index(drop=True)
    df.insert(0, "Rank", df.index + 1)
    return df


def host_summary(plan: pd.DataFrame) -> pd.DataFrame:
    keys = [c for c in ["Host", "Asset_Criticality", "Owner"] if c in plan.columns]
    s = (plan.fillna({"Owner": "Unknown", "Asset_Criticality": "Unknown"})
         .groupby(keys, dropna=False)
         .agg(Finding_Count=("Rank", "count"), Highest_Score=("Priority_Score", "max"),
              Total_Score=("Priority_Score", "sum"))
         .reset_index())
    s["Total_Score"] = s["Total_Score"].round(2)
    return s.sort_values(["Total_Score", "Highest_Score"], ascending=False).reset_index(drop=True)


def _neutralize(v):
    """Prefix a quote when a text cell could be run as a spreadsheet formula."""
    if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + v
    return v


def safe_for_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Neutralize CSV/formula injection in every text column."""
    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_object_dtype(df[c]) or pd.api.types.is_string_dtype(df[c]):
            df[c] = df[c].map(_neutralize)
    return df


# --------------------------------------------------------------------------
# 4. MAIN
# --------------------------------------------------------------------------
def analyze(inv, hf, ports, as_of_arg=None):
    """Core logic with no file I/O. Returns (plan, summary, warnings, as_of)."""
    warns = []
    inv = clean_text(inv, ["Host", "OS_Name", "Asset_Criticality"],
                     upper=("Host",), title=("Asset_Criticality",))
    hf = clean_text(hf, ["Host"], upper=("Host",))
    ports = clean_text(ports, ["Host", "Exposure", "Service"], upper=("Host",), title=("Exposure",))

    if inv.empty:
        raise AnalyzerError("inventory file has no rows")
    if inv["Host"].isna().any():
        warns.append(f"{int(inv['Host'].isna().sum())} inventory row(s) with blank Host ignored")
        inv = inv.dropna(subset=["Host"])
    dup = inv["Host"].duplicated(keep="last")
    if dup.any():
        warns.append(f"duplicate inventory host(s) merged, newest row kept: {sorted(set(inv.loc[dup, 'Host']))}")
        inv = inv.drop_duplicates(subset="Host", keep="last")
    inv = inv.copy()
    inv["OS_Build"] = pd.to_numeric(inv["OS_Build"], errors="coerce")
    bad_b = inv["OS_Build"].isna()
    if bad_b.any():
        warns.append(f"invalid OS_Build, OS check skipped for: {sorted(inv.loc[bad_b, 'Host'])}")
    inv["OS_Build"] = inv["OS_Build"].astype("Int64")

    bad_c = ~inv["Asset_Criticality"].isin(CRITICALITY_MULTIPLIER)
    if bad_c.any():
        warns.append(f"unknown Asset_Criticality (multiplier 1.0 used) for: {sorted(inv.loc[bad_c, 'Host'])}")

    known = set(inv["Host"])
    unknown = (set(hf["Host"].dropna()) | set(ports["Host"].dropna())) - known
    if unknown:
        warns.append(f"hosts not in inventory (ignored): {sorted(unknown)}")
    hf, ports = hf[hf["Host"].isin(known)], ports[ports["Host"].isin(known)]

    # Reference date: scan date (not today) keeps results repeatable
    if as_of_arg:
        as_of = pd.to_datetime(as_of_arg, errors="coerce")
        if pd.isna(as_of):
            raise AnalyzerError(f"--as-of '{as_of_arg}' is not a valid date (use YYYY-MM-DD)")
    elif "Last_Seen" in inv.columns and pd.to_datetime(inv["Last_Seen"], errors="coerce").notna().any():
        as_of = pd.to_datetime(inv["Last_Seen"], errors="coerce").max()
    else:
        as_of = pd.Timestamp.today().normalize()
        warns.append("no usable Last_Seen dates; today's date used as the analysis date")

    future = pd.to_datetime(hf["InstalledOn"], errors="coerce") > as_of
    if future.any():
        warns.append(f"{int(future.sum())} hotfix date(s) are after the analysis date (check data)")

    parts = [os_findings(inv.dropna(subset=["OS_Build"]), as_of), patch_findings(inv, hf, as_of), port_findings(ports)]
    findings = pd.concat([p for p in parts if not p.empty], ignore_index=True) if any(not p.empty for p in parts) \
        else pd.DataFrame(columns=FINDING_COLS)
    plan = build_plan(findings, inv)
    summary = host_summary(plan) if not plan.empty else plan
    return plan, summary, warns, as_of


def main(argv=None):
    ap = argparse.ArgumentParser(description="Vulnerability scan results analyzer")
    ap.add_argument("--inventory", default="os_inventory.csv")
    ap.add_argument("--hotfixes", default="installed_hotfixes.csv")
    ap.add_argument("--ports", default="listening_ports.csv")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--as-of", default=None, help="YYYY-MM-DD; default = newest Last_Seen date")
    a = ap.parse_args(argv)

    inv = load_file(a.inventory, "inventory")
    hf = load_file(a.hotfixes, "hotfixes")
    ports = load_file(a.ports, "ports")
    plan, summary, warns, as_of = analyze(inv, hf, ports, a.as_of)
    for w in warns:
        print("WARNING:", w, file=sys.stderr)
    if plan.empty:
        print(f"Analysis date: {as_of.date()}   No findings.")
        return plan

    os.makedirs(a.outdir, exist_ok=True)
    safe_for_csv(plan).to_csv(os.path.join(a.outdir, "prioritized_remediation_list.csv"), index=False)
    safe_for_csv(summary).to_csv(os.path.join(a.outdir, "host_risk_summary.csv"), index=False)

    print(f"Analysis date: {as_of.date()}   Findings: {len(plan)}   Hosts affected: {len(summary)}\n")
    show = [c for c in ["Rank", "Host", "Asset_Criticality", "Finding_Type", "Base_Score",
                        "Priority_Score", "Priority"] if c in plan.columns]
    print(plan[show].to_string(index=False))
    print("\n--- Host risk summary ---")
    print(summary.to_string(index=False))
    return plan


if __name__ == "__main__":
    try:
        main()
    except AnalyzerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)