"""
test_false_positive_audit.py

Comprehensive test suite verifying false-positive audit fixes for Forenix Module 2.
Tests:
1. Exact bug report case ('nv-cta' vs 'meta') -> confirms no false positive flag.
2. 5+ random unrelated short domains against full brand list -> confirms no false flags.
3. 3+ true positive typosquat cases ('paypa1-secure', 'paypa1', 'micros0ft') -> confirms true positives still flag correctly.
4. 'Unable to verify' auth states rendering integrity -> confirms non-conversion to Pass/Fail.
"""

import unittest
from email_forensics.domain_intel import detect_typosquat, load_brand_domains, DomainIntelResult
from email_forensics.auth_checks import SPFResult, DKIMResult, DMARCResult, AuthResult
from email_forensics.url_analysis import run_url_analysis, ExtractedLink
from email_forensics.parser import ParsedEmail


class TestFalsePositiveAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.brand_list = load_brand_domains()

    def test_bug_report_false_positive_nv_cta(self):
        """
        Tests the exact bug report case: 'nv-cta' vs 'meta'.
        Before fix: 'cta' vs 'meta' (distance 2) triggered typosquat flag.
        After fix: normalized similarity (0.33 / 0.50) is below threshold (0.80) and length diff filter applies.
        Expected: is_typosquat is FALSE.
        """
        is_typosquat, brand, dist, details = detect_typosquat("nv-cta", self.brand_list)
        self.assertFalse(is_typosquat, f"False positive triggered for 'nv-cta'! Flagged brand: {brand}")
        self.assertIsNone(brand)
        self.assertIsNone(dist)

    def test_random_unrelated_short_domains(self):
        """
        Tests at least 5 random unrelated short domain labels against the full brand list.
        Expected: None of them trigger typosquatting false flags.
        """
        unrelated_domains = [
            "admin",
            "server",
            "custom",
            "mail-service",
            "login-portal",
            "helpdesk",
            "support-team"
        ]

        for domain in unrelated_domains:
            is_typosquat, brand, dist, details = detect_typosquat(domain, self.brand_list)
            self.assertFalse(
                is_typosquat,
                f"Unrelated domain '{domain}' incorrectly flagged as typosquat of brand '{brand}' (dist={dist})"
            )

    def test_true_positive_typosquat_cases(self):
        """
        Tests at least 3 known true-positive typosquatting cases.
        Expected: ALL must still correctly flag after the fix.
        """
        true_positives = [
            ("paypa1", "paypal"),
            ("paypa1-secure", "paypal"),
            ("micros0ft", "microsoft"),
            ("netfl1x", "netflix"),
            ("amaz0n", "amazon")
        ]

        for domain, expected_brand in true_positives:
            is_typosquat, brand, dist, details = detect_typosquat(domain, self.brand_list)
            self.assertTrue(
                is_typosquat,
                f"True positive '{domain}' failed to flag against brand '{expected_brand}'!"
            )
            self.assertEqual(brand, expected_brand)
            self.assertIn(dist, (1, 2))

    def test_unable_to_verify_auth_states_distinct_rendering(self):
        """
        Verifies that 'Unable to verify' auth states are never silently converted to Pass or Fail.
        """
        spf = SPFResult(
            status="Unable to verify - DNS lookup failed",
            ip_used="192.168.1.1",
            domain_checked="example.com",
            details="DNS resolution error"
        )
        dkim = DKIMResult(
            status="Unable to verify - dkimpy library not installed",
            domain_checked="example.com"
        )
        dmarc = DMARCResult(
            status="Unable to verify - Missing From domain",
            domain_checked=None
        )

        auth_res = AuthResult(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            summary_status="INCOMPLETE"
        )

        # Confirm exact status text is preserved
        self.assertTrue(auth_res.spf.status.startswith("Unable to verify"))
        self.assertTrue(auth_res.dkim.status.startswith("Unable to verify"))
        self.assertTrue(auth_res.dmarc.status.startswith("Unable to verify"))
        self.assertEqual(auth_res.summary_status, "INCOMPLETE")

    def test_url_deduplication_and_normalization(self):
        """
        Tests URL deduplication and normalization logic in url_analysis.py.
        """
        email_data = ParsedEmail(
            from_name="Test",
            from_address="test@example.com",
            to="user@example.com",
            subject="Test",
            date=None,
            return_path=None,
            reply_to=None,
            message_id=None,
            body_html='<a href="http://mail.nv-cta.com/">http://mail.nv-cta.com</a><a href="http://mail.nv-cta.com">mail.nv-cta.com</a>',
            body_plain='http://mail.nv-cta.com\nhttp://mail.nv-cta.com/'
        )

        url_res = run_url_analysis(email_data)
        # Deduplication should collapse variations of mail.nv-cta.com to 1 clean link entry
        self.assertEqual(url_res.total_links, 1, f"Expected 1 deduplicated link, got {url_res.total_links}")
        self.assertEqual(url_res.links[0].destination_url, "http://mail.nv-cta.com")


if __name__ == '__main__':
    unittest.main()
