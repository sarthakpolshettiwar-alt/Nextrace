"""
test_reputation_checks.py

Unit and Integration tests for Live Reputation Intelligence (email_forensics/reputation_checks.py).
Tests:
- Graceful "not configured" status when VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY are unset
- Graceful "unable to verify" status when external API calls time out or fail
- Rate-limit capping logic (maximum 5 unique URLs checked per email)
- Live API integration verification (when API keys are set in environment)
"""

import os
import unittest
from unittest.mock import patch, MagicMock
import requests

from email_forensics.parser import ParsedEmail
from email_forensics.url_analysis import UrlAnalysisResult, ExtractedLink
from email_forensics.auth_checks import AuthResult, SPFResult
from email_forensics.reputation_checks import (

    run_reputation_checks,
    run_virustotal_checks,
    run_abuseipdb_check,
    ReputationCheckResult,
    MAX_VT_URLS_CHECKED
)


def _load_env_keys():
    """Helper to parse .env file in project root if keys are not set in os.environ."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip("'\"")
                    if k and v and k not in os.environ:
                        os.environ[k] = v


class TestReputationChecks(unittest.TestCase):

    def setUp(self):
        """Store original environment variables and load .env if available."""
        _load_env_keys()
        self.orig_vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.orig_abuse_key = os.environ.get("ABUSEIPDB_API_KEY")


    def tearDown(self):
        """Restore original environment variables."""
        if self.orig_vt_key is not None:
            os.environ["VIRUSTOTAL_API_KEY"] = self.orig_vt_key
        else:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)

        if self.orig_abuse_key is not None:
            os.environ["ABUSEIPDB_API_KEY"] = self.orig_abuse_key
        else:
            os.environ.pop("ABUSEIPDB_API_KEY", None)

    def test_01_keys_unset_graceful_not_configured(self):
        """Test that missing API keys return 'Reputation check not configured' without crashing."""
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        os.environ.pop("ABUSEIPDB_API_KEY", None)

        parsed = ParsedEmail(from_name="Test", from_address="u@e.com", to="t@e.com", subject="S", date=None, return_path=None, reply_to=None, message_id="<m@e.com>")
        res = run_reputation_checks(parsed)

        self.assertFalse(res.virustotal.is_configured)
        self.assertEqual(res.virustotal.status, "Reputation check not configured")
        self.assertFalse(res.abuseipdb.is_configured)
        self.assertEqual(res.abuseipdb.status, "Reputation check not configured")

    def test_02_mocked_timeout_graceful_unable_to_verify(self):
        """Test that API timeout/failure returns 'Unable to verify' without failing pipeline."""
        os.environ["VIRUSTOTAL_API_KEY"] = "mock_vt_key"
        os.environ["ABUSEIPDB_API_KEY"] = "mock_abuse_key"

        with patch("requests.get", side_effect=requests.Timeout("Connection timed out")):
            parsed = ParsedEmail(from_name="Test", from_address="u@e.com", to="t@e.com", subject="S", date=None, return_path=None, reply_to=None, message_id="<m@e.com>")
            url_res = UrlAnalysisResult(status="Completed", links=[ExtractedLink(link_text="click", destination_url="https://example.com/link1")])
            auth_res = AuthResult(spf=SPFResult(status="Pass", ip_used="198.51.100.1", domain_checked="example.com"), dkim=None, dmarc=None, summary_status="Pass")



            res = run_reputation_checks(parsed, url_result=url_res, auth_result=auth_res, timeout=1)

            self.assertTrue(res.virustotal.is_configured)
            self.assertEqual(len(res.virustotal.urls_checked), 1)
            self.assertIn("Unable to verify", res.virustotal.urls_checked[0].status)

            self.assertTrue(res.abuseipdb.is_configured)
            self.assertIn("Unable to verify", res.abuseipdb.status)

    def test_03_url_rate_limit_capping_max_5(self):
        """Test that email with > 5 URLs caps VirusTotal checks at MAX_VT_URLS_CHECKED (5)."""
        os.environ["VIRUSTOTAL_API_KEY"] = "mock_vt_key"

        urls = [f"https://domain{i}.com/path" for i in range(10)]
        url_items = [ExtractedLink(link_text="link", destination_url=u) for u in urls]
        url_res = UrlAnalysisResult(status="Completed", links=url_items)


        mock_response = MagicMock()
        mock_response.status_code = 404  # Not previously scanned

        with patch("requests.get", return_value=mock_response):
            vt_res = run_virustotal_checks(urls, timeout=1)

            self.assertEqual(vt_res.total_urls_found, 10)
            self.assertEqual(vt_res.checked_count, MAX_VT_URLS_CHECKED)
            self.assertEqual(len(vt_res.urls_checked), MAX_VT_URLS_CHECKED)
            self.assertIn("Checked 5 of 10 URLs", vt_res.disclosure_note)

    def test_04_live_api_integration_if_keys_present(self):
        """Live API integration test if VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY are configured."""
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        abuse_key = os.environ.get("ABUSEIPDB_API_KEY")

        if not vt_key or not abuse_key:
            self.skipTest("Skipping live API integration test as API keys are not set in environment.")

        parsed = ParsedEmail(from_name="Google", from_address="no-reply@google.com", to="u@e.com", subject="Alert", date=None, return_path=None, reply_to=None, message_id="<m@e.com>")
        url_res = UrlAnalysisResult(status="Completed", links=[ExtractedLink(link_text="Google", destination_url="https://google.com")])
        auth_res = AuthResult(spf=SPFResult(status="Pass", ip_used="8.8.8.8", domain_checked="google.com"), dkim=None, dmarc=None, summary_status="Pass")





        res = run_reputation_checks(parsed, url_result=url_res, auth_result=auth_res, timeout=5)

        self.assertTrue(res.virustotal.is_configured)
        self.assertGreaterEqual(len(res.virustotal.urls_checked), 1)
        self.assertTrue(res.abuseipdb.is_configured)
        self.assertIsNotNone(res.abuseipdb.status)
        print(f"\n[LIVE API VERIFICATION RESULT]")
        print(f" VirusTotal Status : {res.virustotal.status}")
        print(f" AbuseIPDB Status   : {res.abuseipdb.status} (Score: {res.abuseipdb.abuse_confidence_score}%)")



if __name__ == "__main__":
    unittest.main()
