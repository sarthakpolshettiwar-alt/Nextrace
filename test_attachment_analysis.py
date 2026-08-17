"""
test_attachment_analysis.py

Test suite for Attachment Risk Analysis Layer in Forenix Module 2.
Tests:
1. Clean PDF attachment (real %PDF bytes) -> expect 0 flags.
2. Fake PDF attachment (rename .exe MZ bytes to "invoice.pdf") -> signature mismatch detected via magic bytes.
3. Double extension trick ("report.pdf.exe") -> double extension flag & dangerous extension flag fire.
4. Honestly named dangerous extension ("script.js") -> dangerous extension flag fires, no double extension/mismatch.
5. Legitimately dotted filename ("quarterly.report.v2.pdf") -> no false double extension flag.
6. Zero attachments case -> clean empty list, no errors.
7. Unextracted content case (att.content is None) -> explicitly returns 'Not available — attachment content not extracted'.
"""

import unittest
from email_forensics.parser import ParsedEmail, EmailAttachment
from email_forensics.attachment_analysis import (
    run_attachment_analysis,
    detect_double_extension,
    detect_magic_bytes,
    detect_signature_mismatch,
    load_dangerous_extensions
)


class TestAttachmentAnalysis(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dangerous_exts = load_dangerous_extensions()

    def test_clean_pdf_attachment(self):
        """Clean PDF attachment with real %PDF bytes should raise 0 risk flags."""
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
        att = EmailAttachment(
            filename="quarterly_report.pdf",
            size=len(pdf_bytes),
            content=pdf_bytes
        )
        email = ParsedEmail(
            from_name="Finance", from_address="finance@corp.com",
            to="user@corp.com", subject="Report", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        self.assertEqual(res.suspicious_attachments_count, 0)
        self.assertFalse(res.has_dangerous_extension)
        self.assertFalse(res.has_double_extension)
        self.assertFalse(res.has_signature_mismatch)
        item = res.attachments[0]
        self.assertEqual(item.claimed_extension, ".pdf")
        self.assertIn("pdf", item.detected_mime.lower())

    def test_fake_pdf_exe_mismatch(self):
        """Windows Executable (MZ bytes) disguised as 'invoice.pdf' must trigger signature mismatch via magic bytes."""
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."
        att = EmailAttachment(
            filename="invoice.pdf",
            size=len(exe_bytes),
            content=exe_bytes
        )
        email = ParsedEmail(
            from_name="Accounts", from_address="billing@vendor.com",
            to="user@corp.com", subject="Invoice", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        self.assertEqual(res.suspicious_attachments_count, 1)
        self.assertTrue(res.has_signature_mismatch)
        item = res.attachments[0]
        self.assertTrue(item.is_signature_mismatch)
        self.assertIn("File signature mismatch", item.signature_mismatch_details)

    def test_double_extension_trick(self):
        """'report.pdf.exe' must trigger both double-extension and dangerous-extension flags."""
        exe_bytes = b"MZ\x90\x00\x03\x00..."
        att = EmailAttachment(
            filename="report.pdf.exe",
            size=len(exe_bytes),
            content=exe_bytes
        )
        email = ParsedEmail(
            from_name="HR", from_address="hr@corp.com",
            to="user@corp.com", subject="Report", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        self.assertEqual(res.suspicious_attachments_count, 1)
        self.assertTrue(res.has_double_extension)
        self.assertTrue(res.has_dangerous_extension)
        item = res.attachments[0]
        self.assertTrue(item.is_double_extension)
        self.assertTrue(item.is_dangerous_extension)

    def test_dangerous_extension_honest_name(self):
        """'script.js' must trigger dangerous-extension flag, but NOT double-extension or signature-mismatch."""
        js_bytes = b"var x = 10; console.log(x);"
        att = EmailAttachment(
            filename="script.js",
            size=len(js_bytes),
            content=js_bytes
        )
        email = ParsedEmail(
            from_name="Dev", from_address="dev@corp.com",
            to="user@corp.com", subject="Code", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        self.assertTrue(res.has_dangerous_extension)
        self.assertFalse(res.has_double_extension)
        self.assertFalse(res.has_signature_mismatch)
        item = res.attachments[0]
        self.assertTrue(item.is_dangerous_extension)
        self.assertFalse(item.is_double_extension)
        self.assertFalse(item.is_signature_mismatch)

    def test_legitimate_multi_dot_filename(self):
        """Legitimately dotted filename 'quarterly.report.v2.pdf' must NOT falsely trigger double-extension detection."""
        pdf_bytes = b"%PDF-1.5\n%%EOF"
        att = EmailAttachment(
            filename="quarterly.report.v2.pdf",
            size=len(pdf_bytes),
            content=pdf_bytes
        )
        email = ParsedEmail(
            from_name="Analyst", from_address="analyst@corp.com",
            to="user@corp.com", subject="Draft", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        self.assertFalse(res.has_double_extension)
        item = res.attachments[0]
        self.assertFalse(item.is_double_extension)

    def test_zero_attachments_clean_handling(self):
        """Zero attachments must return a clean AttachmentAnalysisResult with empty list."""
        email = ParsedEmail(
            from_name="Sender", from_address="sender@corp.com",
            to="user@corp.com", subject="No attachments", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.total_attachments, 0)
        self.assertEqual(res.suspicious_attachments_count, 0)
        self.assertEqual(res.attachments, [])

    def test_unextracted_content_not_available_state(self):
        """If attachment content is None (unextracted/metadata only), signature check must return 'Not available'."""
        att = EmailAttachment(
            filename="unknown_file.pdf",
            size=1024,
            content=None
        )
        email = ParsedEmail(
            from_name="Sender", from_address="sender@corp.com",
            to="user@corp.com", subject="Metadata only", date=None,
            return_path=None, reply_to=None, message_id=None,
            attachments=[att]
        )

        res = run_attachment_analysis(email)
        self.assertEqual(res.total_attachments, 1)
        item = res.attachments[0]
        self.assertIn("Not available — attachment content not extracted", item.detected_mime)
        self.assertIn("Not available — attachment content not extracted", item.signature_mismatch_details)
        self.assertFalse(item.is_signature_mismatch)


if __name__ == '__main__':
    unittest.main()
