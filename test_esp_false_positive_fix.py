"""
test_esp_false_positive_fix.py

Tests ESP false positive reduction (Task A, B, C verification) in Forenix Module 2.
1. Verifies that legitimate ESP email (e.g. L&T Technology Services campus placement confirmation via Superset & Amazon SES)
   scores low/medium risk (score <= 15) instead of false-positive High Risk (52/100).
2. Verifies that real phishing emails (non-ESP return-path mismatch, brand impersonation, bad links) STILL score as High Risk / Likely Spoofed.
"""

import os
import unittest
from pathlib import Path

from email.message import EmailMessage
from datetime import datetime, timezone

from email_forensics.parser import ParsedEmail

from email_forensics.auth_checks import AuthResult, SPFResult, DKIMResult, DMARCResult
from email_forensics.domain_intel import run_domain_intel, is_known_esp
from email_forensics.url_analysis import run_url_analysis
from email_forensics.header_integrity import run_header_integrity_check
from email_forensics.html_analysis import run_html_analysis
from email_forensics.content_analysis import run_content_analysis
from email_forensics.domain_age import run_domain_age_check
from email_forensics.reputation_checks import run_reputation_checks
from email_forensics.risk_scoring import calculate_risk_score





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


class TestEspFalsePositiveFix(unittest.TestCase):

    def setUp(self):
        _load_env_keys()


    def test_01_known_esp_domain_recognition(self):
        """Verify that known ESP domains are correctly recognized by is_known_esp."""
        self.assertTrue(is_known_esp("amazonses.com"))
        self.assertTrue(is_known_esp("pe2a-us-east-1.amazonses.com"))
        self.assertTrue(is_known_esp("awstrack.me"))
        self.assertTrue(is_known_esp("sendgrid.net"))
        self.assertTrue(is_known_esp("mailchimp.com"))
        self.assertFalse(is_known_esp("evil-phishing-host.com"))

    def test_02_lt_superset_campus_email_false_positive_reduction(self):
        """
        Re-run L&T Technology Services application confirmation email sent via Superset / Amazon SES:
        From: L&T Technology Services <careers@ltts.com>
        Return-Path: <20260807-bounce@pe2a-us-east-1.amazonses.com>
        Link: Visible text 'https://ltts.com/careers/confirm', Destination 'https://awstrack.me/L0/http.../ltts'
        
        BEFORE FIX: Scored 52/100 (High Risk) due to:
        - Return-Path mismatch (+10 pts)
        - Link Brand Impersonation (+15 pts)
        - Link Domain Mismatch (+15 pts)
        - SPF/DMARC alignment (+12 pts)
        
        AFTER FIX: Scores <= 15 (Low / Medium Risk).
        """
        parsed_email = ParsedEmail(
            from_name="L&T Technology Services Campus Recruitment",
            from_address="careers@ltts.com",
            to="student@university.edu",
            subject="Application Confirmation - L&T Technology Services Placement Drive",
            date="Fri, 07 Aug 2026 10:00:00 +0000",
            return_path="20260807-bounce@pe2a-us-east-1.amazonses.com",
            reply_to="no-reply@join-superset.com",
            message_id="<01000185-ltts-amazonses@email.amazonses.com>",
            received_headers=[
                "from a8-25.smtp-out.amazonses.com (a8-25.smtp-out.amazonses.com [54.240.8.25]) by mx.google.com with ESMTPS"
            ],
            body_plain="Dear Candidate, Your application for L&T Technology Services placement has been confirmed. Visit https://ltts.com/careers/confirm to track status.",
            body_html='''
            <html>
            <body>
                <p>Dear Candidate,</p>
                <p>Your application for <strong>L&T Technology Services</strong> campus placement has been confirmed.</p>
                <p><a href="https://awstrack.me/L0/http://ltts.com/careers/confirm">https://ltts.com/careers/confirm</a></p>
            </body>
            </html>
            ''',
            attachments=[]
        )

        auth_res = AuthResult(
            summary_status="PASS",
            spf=SPFResult(status="Pass", ip_used="54.240.8.25", domain_checked="amazonses.com", raw_record="v=spf1 include:amazonses.com ~all"),
            dkim=DKIMResult(status="Pass", domain_checked="ltts.com", selector="s2026"),
            dmarc=DMARCResult(status="Pass", domain_checked="ltts.com", policy="none")
        )


        now_ts = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        dom_res = run_domain_intel(parsed_email)
        url_res = run_url_analysis(parsed_email)
        hdr_res = run_header_integrity_check(parsed_email, now=now_ts)
        html_res = run_html_analysis(parsed_email)
        cnt_res = run_content_analysis(parsed_email)
        age_res = run_domain_age_check(parsed_email, now=now_ts)
        rep_res = run_reputation_checks(parsed_email, url_result=url_res, auth_result=auth_res)

        risk_res = calculate_risk_score(
            parsed_email, auth_res, dom_res, url_res, None,
            hdr_res, html_res, cnt_res, age_res, rep_res
        )



        print("\n" + "="*80)
        print(" L&T / SUPERSET CAMPUS EMAIL BEFORE VS AFTER SCORE EVALUATION")
        print("="*80)
        print(f" Before Fix Score  : 52 / 100 [High Risk] (FALSE POSITIVE)")
        print(f" After Fix Score   : {risk_res.total_score} / 100 [{risk_res.risk_band}]")
        print(f" Hard Flagged      : {risk_res.hard_flagged}")
        print(f" Assessment Note   : {risk_res.verdict_explanation}")
        print(" Audit Breakdown:")
        for item in risk_res.breakdown:
            print(f"   - [{item.category}] {item.rule_name}: {item.state} (+{item.points_added})")
        print("="*80 + "\n")

        # Verify score dropped significantly (should be <= 15, i.e. Low or Low-Medium Risk, not High Risk)
        self.assertLessEqual(risk_res.total_score, 15, f"Score should drop to <= 15, got {risk_res.total_score}")
        self.assertIn(risk_res.risk_band, ["Low Risk", "Medium Risk"])
        self.assertFalse(risk_res.hard_flagged)

        # Verify ESP note present on link
        esp_link_flagged = any("known ESP tracking domain" in f for l in url_res.links for f in l.flags)
        self.assertTrue(esp_link_flagged, "Informational ESP tracking note should be present on awstrack.me link")

    def test_03_real_phishing_email_remains_high_risk(self):
        """
        Verify that a real phishing email (non-ESP return-path mismatch + brand impersonation + raw IP link)
        STILL scores as High Risk / Likely Spoofed.
        """
        parsed_email = ParsedEmail(
            from_name="PayPal Support",
            from_address="security@paypal-update-info.com",
            to="victim@company.com",
            subject="Urgent: Account Suspended - Verify Identity Immediately",
            date="Fri, 07 Aug 2026 10:00:00 +0000",
            return_path="spammer@evil-phishing-relay.xyz",
            reply_to="hacker@malicious-domain.com",
            message_id="<fake-12345@evil-phishing-relay.xyz>",
            received_headers=[],
            body_plain="Verify your PayPal account now: http://192.168.1.100/login",
            body_html='''
            <html>
            <body>
                <p>Verify your <strong>PayPal</strong> account immediately:</p>
                <a href="http://192.168.1.100/paypal/login">https://paypal.com/signin</a>
            </body>
            </html>
            ''',
            attachments=[]
        )

        auth_res = AuthResult(
            summary_status="FAIL",
            spf=SPFResult(status="Fail", ip_used="192.168.1.100", domain_checked="paypal-update-info.com"),
            dkim=DKIMResult(status="Fail", domain_checked="paypal-update-info.com"),
            dmarc=DMARCResult(status="Fail", domain_checked="paypal-update-info.com")
        )


        now_ts = datetime(2026, 8, 7, 10, 0, 0, tzinfo=timezone.utc)
        dom_res = run_domain_intel(parsed_email)
        url_res = run_url_analysis(parsed_email)
        hdr_res = run_header_integrity_check(parsed_email, now=now_ts)
        html_res = run_html_analysis(parsed_email)
        cnt_res = run_content_analysis(parsed_email)
        age_res = run_domain_age_check(parsed_email, now=now_ts)
        rep_res = run_reputation_checks(parsed_email, url_result=url_res, auth_result=auth_res)

        risk_res = calculate_risk_score(
            parsed_email, auth_res, dom_res, url_res, None,
            hdr_res, html_res, cnt_res, age_res, rep_res
        )



        print("\n" + "="*80)
        print(" REAL PHISHING EMAIL VERIFICATION")
        print("="*80)
        print(f" Score       : {risk_res.total_score} / 100 [{risk_res.risk_band}]")
        print(f" Hard Flagged: {risk_res.hard_flagged}")
        print(" Audit Breakdown:")
        for item in risk_res.breakdown:
            print(f"   - [{item.category}] {item.rule_name}: {item.state} (+{item.points_added})")
        print("="*80 + "\n")

        # Verify real phishing still scores High Risk / Likely Spoofed
        self.assertTrue(risk_res.hard_flagged or risk_res.total_score >= 60)
        self.assertIn(risk_res.risk_band, ["Likely Spoofed", "High Risk"])


if __name__ == '__main__':
    unittest.main()
