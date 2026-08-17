"""
test_content_analysis.py

Unit tests for Content & Keyword Analysis (email_forensics/content_analysis.py).
Tests:
- Clean email content without scam keywords
- Phishing email with urgency, credential theft, and banking keywords
- Category grouping and exact phrase match evidence
"""

import unittest
from email_forensics.parser import ParsedEmail
from email_forensics.content_analysis import run_content_analysis


class TestContentAnalysis(unittest.TestCase):

    def test_01_clean_email_content(self):
        """Test a clean email containing standard corporate communication."""
        parsed = ParsedEmail(
            from_name="HR Team",
            from_address="hr@company.com",
            to="employee@company.com",
            subject="Quarterly Town Hall Meeting Scheduled",
            date=None, return_path=None, reply_to=None, message_id="<m1@c.com>",
            body_plain="Please join us for our quarterly town hall meeting next Tuesday at 10 AM. Agenda items include team updates and Q&A.",
            body_html="<p>Please join us for our quarterly town hall meeting next Tuesday at 10 AM.</p>"
        )
        res = run_content_analysis(parsed)
        self.assertEqual(res.total_categories_count, 0)
        self.assertEqual(res.total_matches_count, 0)

    def test_02_phishing_scam_keywords_detected(self):
        """Test a phishing email containing urgency, credential theft, and banking keywords."""
        parsed = ParsedEmail(
            from_name="Bank Security Department",
            from_address="alert@bank-security-update.com",
            to="victim@company.com",
            subject="Urgent Action Required: Bank Account Frozen",
            date=None, return_path=None, reply_to=None, message_id="<m2@evil.com>",
            body_plain="Urgent action required! Your bank account frozen due to unauthorized login attempt. Click here to verify your password and confirm your identity within 24 hours to respond.",
            body_html="<p><strong>Urgent action required!</strong> Your <strong>bank account frozen</strong>. <a>click here to verify</a> your password immediately.</p>"
        )
        res = run_content_analysis(parsed)
        self.assertGreaterEqual(res.total_categories_count, 3)
        self.assertGreaterEqual(res.total_matches_count, 3)

        category_names = [c.category_name for c in res.categories_flagged]
        self.assertIn("urgency", category_names)
        self.assertIn("credential_theft", category_names)
        self.assertIn("banking", category_names)

        # Check evidence contains exact matched phrases
        evidence_str = " ".join([f['evidence'] for f in res.findings])
        self.assertIn("urgent action required", evidence_str)
        self.assertIn("bank account frozen", evidence_str)


if __name__ == '__main__':
    unittest.main()
