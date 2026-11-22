# -*- coding: utf-8 -*-
"""
Created on Sun Nov 22 16:31:23 2026

@author: h31sy
"""

"""Test cases for ac2_final.py: known inputs compared with expected results."""
import unittest
from datetime import datetime, timedelta

import ac2_final as m

NOW = datetime(2026, 11, 21, 12, 0, 0)


def user(name, enabled=True, sid="S-1-5-21-1-1001", last=None, expires=None, pw=True):
    return {"Name": name, "Enabled": enabled, "Sid": sid, "LastLogonDt": last,
            "AccountExpiresDt": expires, "PasswordRequired": pw}


SAMPLE_AUDIT = (
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n"
    "PC,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,\n"
    "PC,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success,\n")
BAD_AUDIT = SAMPLE_AUDIT.replace("Success and Failure", "No Auditing")


class TestAC2(unittest.TestCase):
    def test_parse_dt(self):
        self.assertEqual(m.parse_dt("2026-11-01T08:30:00"), datetime(2026, 11, 1, 8, 30))
        self.assertIsNone(m.parse_dt(None))
        self.assertIsNone(m.parse_dt("not a date"))

    def test_guest_enabled_by_sid_even_if_renamed(self):
        f = m.check_default_accounts([user("Visitor", sid="S-1-5-21-1-501")])
        self.assertEqual(f["status"], "REVIEW")
        self.assertIn("Visitor", f["detail"])

    def test_default_accounts_all_disabled(self):
        f = m.check_default_accounts([user("Guest", False, "S-1-5-21-1-501"), user("Ski")])
        self.assertEqual(f["status"], "PASS")

    def test_expired_account_fails(self):
        f1, _ = m.check_expired_inactive([user("old", expires=NOW - timedelta(days=1))], 90, NOW)
        self.assertEqual(f1["status"], "FAIL")

    def test_future_expiry_passes(self):
        f1, _ = m.check_expired_inactive([user("new", last=NOW, expires=NOW + timedelta(days=30))], 90, NOW)
        self.assertEqual(f1["status"], "PASS")

    def test_inactive_120_days_flagged(self):
        _, f2 = m.check_expired_inactive([user("idle", last=NOW - timedelta(days=120))], 90, NOW)
        self.assertEqual(f2["status"], "REVIEW")
        self.assertIn("120 days", f2["detail"])

    def test_recent_logon_passes(self):
        _, f2 = m.check_expired_inactive([user("busy", last=NOW - timedelta(days=5))], 90, NOW)
        self.assertEqual(f2["status"], "PASS")

    def test_disabled_accounts_ignored(self):
        f1, f2 = m.check_expired_inactive(
            [user("off", False, last=NOW - timedelta(days=500), expires=NOW - timedelta(days=9))], 90, NOW)
        self.assertEqual((f1["status"], f2["status"]), ("PASS", "PASS"))

    def test_never_logged_on_needs_review(self):
        _, f2 = m.check_expired_inactive([user("ghost", last=None)], 90, NOW)
        self.assertEqual(f2["status"], "REVIEW")

    def test_password_not_required(self):
        self.assertEqual(m.check_password_required([user("nopw", pw=False)])["status"], "REVIEW")
        self.assertEqual(m.check_password_required([user("ok")])["status"], "INFO")

    def test_audit_good_and_bad(self):
        self.assertEqual(m.audit_finding(m.parse_audit(SAMPLE_AUDIT))["status"], "PASS")
        self.assertEqual(m.audit_finding(m.parse_audit(BAD_AUDIT))["status"], "FAIL")

    def test_summarize_verdicts(self):
        mk = lambda s: m.finding("x", "AC-2", "t", s, "d")
        self.assertEqual(m.summarize([mk("PASS"), mk("FAIL")])[1], "FAILURES FOUND")
        self.assertEqual(m.summarize([mk("PASS"), mk("REVIEW")])[1], "MANUAL REVIEW REQUIRED")
        self.assertEqual(m.summarize([mk("PASS"), mk("INFO")])[1], "NO TECHNICAL FAILURES FOUND")


if __name__ == "__main__":
    unittest.main(verbosity=2)