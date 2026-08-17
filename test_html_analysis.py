"""
test_html_analysis.py

Unit tests for HTML Content Analysis (email_forensics/html_analysis.py).
Tests:
- Hidden text detection (display:none, visibility:hidden, font-size 0, matching font/bg color)
- Invisible / disguised links (empty <a> text, 1x1 pixel tracking images)
- JavaScript redirect & meta refresh detection
- Iframe tag detection
- Large obfuscated Base64 data payload detection (>10KB)
"""

import unittest
from email_forensics.parser import ParsedEmail
from email_forensics.html_analysis import run_html_analysis


class TestHTMLAnalysis(unittest.TestCase):

    def test_01_clean_html(self):
        """Test clean HTML body with standard tags."""
        html = "<html><body><h1>Hello World</h1><p>Welcome to our platform. <a href='https://example.com'>Click here</a></p></body></html>"
        parsed = ParsedEmail(
            from_name="User", from_address="u@e.com", to="t@e.com", subject="Subj",
            date=None, return_path=None, reply_to=None, message_id="<m@e.com>",
            body_html=html
        )
        res = run_html_analysis(parsed)
        self.assertFalse(res.has_hidden_text)
        self.assertFalse(res.has_invisible_links)
        self.assertFalse(res.has_js_redirect)
        self.assertFalse(res.has_iframe)
        self.assertFalse(res.has_large_base64)

    def test_02_hidden_text_detection(self):
        """Test detection of display:none, font-size:0, and matching font/bg color."""
        html = """
        <html>
        <body>
            <p style="display:none">Hidden payload text for spam filter bypass</p>
            <span style="font-size:0px">Zero font text</span>
            <div style="color:#ffffff; background-color:#ffffff">White text on white background</div>
        </body>
        </html>
        """
        parsed = ParsedEmail(
            from_name="User", from_address="u@e.com", to="t@e.com", subject="Subj",
            date=None, return_path=None, reply_to=None, message_id="<m@e.com>",
            body_html=html
        )
        res = run_html_analysis(parsed)
        self.assertTrue(res.has_hidden_text)
        self.assertGreaterEqual(len(res.hidden_text_evidence), 3)

    def test_03_invisible_links_detection(self):
        """Test empty link text and 1x1 pixel link tracking images."""
        html = """
        <html>
        <body>
            <a href="https://phishing.com"></a>
            <a href="https://tracker.com"><img src="pixel.gif" width="1" height="1" /></a>
        </body>
        </html>
        """
        parsed = ParsedEmail(
            from_name="User", from_address="u@e.com", to="t@e.com", subject="Subj",
            date=None, return_path=None, reply_to=None, message_id="<m@e.com>",
            body_html=html
        )
        res = run_html_analysis(parsed)
        self.assertTrue(res.has_invisible_links)
        self.assertEqual(len(res.invisible_links_evidence), 2)

    def test_04_js_redirect_and_iframe(self):
        """Test JavaScript redirects, meta refresh, and iframe tags."""
        html = """
        <html>
        <head>
            <meta http-equiv="refresh" content="0;url=https://evil.com/redirect">
        </head>
        <body>
            <script>window.location.href = "https://evil.com/login";</script>
            <iframe src="https://evil.com/payload"></iframe>
        </body>
        </html>
        """
        parsed = ParsedEmail(
            from_name="User", from_address="u@e.com", to="t@e.com", subject="Subj",
            date=None, return_path=None, reply_to=None, message_id="<m@e.com>",
            body_html=html
        )
        res = run_html_analysis(parsed)
        self.assertTrue(res.has_js_redirect)
        self.assertTrue(res.has_iframe)

    def test_05_large_base64_payload(self):
        """Test detection of large Base64 embedded data URI payloads (>10KB)."""
        large_payload = "A" * 12000
        html = f"<html><body><img src='data:image/png;base64,{large_payload}' /></body></html>"
        parsed = ParsedEmail(
            from_name="User", from_address="u@e.com", to="t@e.com", subject="Subj",
            date=None, return_path=None, reply_to=None, message_id="<m@e.com>",
            body_html=html
        )
        res = run_html_analysis(parsed)
        self.assertTrue(res.has_large_base64)


if __name__ == '__main__':
    unittest.main()
