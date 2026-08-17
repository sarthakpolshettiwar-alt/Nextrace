"""
test_header_integrity.py

Unit tests for Header Integrity Analysis (email_forensics/header_integrity.py).
Tests:
- Message-ID validation (missing, malformed, valid)
- Duplicate critical header detection (From, Subject)
- Missing critical headers (Date, Message-ID, From)
- Date header sanity (future-dated, implausibly old)
- X-Originating-IP extraction
"""

import unittest
from datetime import datetime, timezone, timedelta
from email_forensics.parser import ParsedEmail
from email_forensics.header_integrity import run_header_integrity_check


class TestHeaderIntegrity(unittest.TestCase):

    def test_01_valid_header_integrity(self):
        """Test a clean email with valid headers."""
        now = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        parsed = ParsedEmail(
            from_name="Alice",
            from_address="alice@example.com",
            to="bob@example.com",
            subject="Meeting Minutes",
            date=datetime(2026, 8, 7, 9, 30, 0, tzinfo=timezone.utc),
            return_path="alice@example.com",
            reply_to=None,
            message_id="<12345.abcdef@example.com>",
            all_headers=[
                {"name": "From", "value": "Alice <alice@example.com>"},
                {"name": "To", "value": "bob@example.com"},
                {"name": "Subject", "value": "Meeting Minutes"},
                {"name": "Date", "value": "Fri, 07 Aug 2026 09:30:00 +0000"},
                {"name": "Message-ID", "value": "<12345.abcdef@example.com>"}
            ]
        )
        res = run_header_integrity_check(parsed, now=now)
        self.assertFalse(res.is_message_id_missing)
        self.assertFalse(res.is_message_id_malformed)
        self.assertEqual(len(res.duplicate_headers), 0)
        self.assertEqual(len(res.missing_critical_headers), 0)
        self.assertFalse(res.is_date_future)
        self.assertFalse(res.is_date_implausible)

    def test_02_duplicate_headers_detection(self):
        """Test detection of duplicated critical headers (header injection attack)."""
        now = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        parsed = ParsedEmail(
            from_name="Attacker",
            from_address="hacker@evil.com",
            to="victim@company.com",
            subject="Fake Subject",
            date=datetime(2026, 8, 7, 9, 30, 0, tzinfo=timezone.utc),
            return_path=None,
            reply_to=None,
            message_id="<msg123@evil.com>",
            all_headers=[
                {"name": "From", "value": "CEO <ceo@company.com>"},
                {"name": "From", "value": "Attacker <hacker@evil.com>"},
                {"name": "Subject", "value": "Legit Subject"},
                {"name": "Subject", "value": "Phishing Subject"},
                {"name": "Date", "value": "Fri, 07 Aug 2026 09:30:00 +0000"},
                {"name": "Message-ID", "value": "<msg123@evil.com>"}
            ]
        )
        res = run_header_integrity_check(parsed, now=now)
        self.assertIn("From", res.duplicate_headers)
        self.assertIn("Subject", res.duplicate_headers)
        self.assertGreaterEqual(len(res.findings), 2)

    def test_03_malformed_and_missing_message_id(self):
        """Test missing and malformed Message-ID headers."""
        now = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        
        # Missing Message-ID
        parsed_missing = ParsedEmail(
            from_name="User", from_address="user@test.com", to="to@test.com",
            subject="Test", date=now, return_path=None, reply_to=None, message_id=None
        )
        res_missing = run_header_integrity_check(parsed_missing, now=now)
        self.assertTrue(res_missing.is_message_id_missing)

        # Malformed Message-ID (no @ symbol or domain)
        parsed_malformed = ParsedEmail(
            from_name="User", from_address="user@test.com", to="to@test.com",
            subject="Test", date=now, return_path=None, reply_to=None, message_id="INVALID_MSG_ID_123"
        )
        res_malformed = run_header_integrity_check(parsed_malformed, now=now)
        self.assertTrue(res_malformed.is_message_id_malformed)

    def test_04_date_sanity_checks(self):
        """Test future-dated and implausibly old email dates."""
        now = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)

        # Future-dated (> 1 hr in future)
        future_dt = now + timedelta(days=2)
        parsed_future = ParsedEmail(
            from_name="User", from_address="u@t.com", to="b@t.com", subject="S",
            date=future_dt, return_path=None, reply_to=None, message_id="<m@t.com>"
        )
        res_future = run_header_integrity_check(parsed_future, now=now)
        self.assertTrue(res_future.is_date_future)

        # Implausibly old (< 1990)
        old_dt = datetime(1970, 1, 1, tzinfo=timezone.utc)
        parsed_old = ParsedEmail(
            from_name="User", from_address="u@t.com", to="b@t.com", subject="S",
            date=old_dt, return_path=None, reply_to=None, message_id="<m@t.com>"
        )
        res_old = run_header_integrity_check(parsed_old, now=now)
        self.assertTrue(res_old.is_date_implausible)

    def test_05_x_originating_ip_extraction(self):
        """Test extraction of X-Originating-IP header."""
        now = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        parsed = ParsedEmail(
            from_name="User", from_address="u@t.com", to="b@t.com", subject="S",
            date=now, return_path=None, reply_to=None, message_id="<m@t.com>",
            all_headers=[
                {"name": "X-Originating-IP", "value": "[198.51.100.42]"}
            ]
        )
        res = run_header_integrity_check(parsed, now=now)
        self.assertEqual(res.x_originating_ip, "198.51.100.42")


if __name__ == '__main__':
    unittest.main()
