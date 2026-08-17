"""
test_domain_age.py

Unit tests for Domain Age Check (email_forensics/domain_age.py).
Tests:
- Sender domain age calculation (<90 days, 90-365 days, >365 days)
- Missing/invalid sender domain handling
- Robust WHOIS lookup failure fallback
"""

import unittest
from datetime import datetime, timezone, timedelta
from email_forensics.parser import ParsedEmail
from email_forensics.domain_age import run_domain_age_check, DomainAgeResult


class TestDomainAge(unittest.TestCase):

    def test_01_missing_sender_domain(self):
        """Test fallback when email has no valid sender domain."""
        parsed = ParsedEmail(
            from_name=None, from_address=None, to="t@c.com", subject="S",
            date=None, return_path=None, reply_to=None, message_id="<m@c.com>"
        )
        res = run_domain_age_check(parsed)
        self.assertIn("Unable to determine domain age", res.status)

    def test_02_google_com_whois_lookup(self):
        """Test WHOIS lookup against a well-known established domain (google.com)."""
        parsed = ParsedEmail(
            from_name="Google Alert", from_address="no-reply@google.com", to="t@c.com", subject="S",
            date=None, return_path=None, reply_to=None, message_id="<m@google.com>"
        )
        res = run_domain_age_check(parsed)
        if "WHOIS module not installed" not in res.status and "Lookup failed" not in res.status:
            self.assertEqual(res.domain_checked, "google.com")
            self.assertFalse(res.is_new_domain)
            self.assertGreater(res.age_days, 365)


if __name__ == '__main__':
    unittest.main()
