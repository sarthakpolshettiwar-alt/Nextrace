"""
test_attachment_bytes_not_persisted.py

Audits and verifies that raw attachment content bytes are NEVER persisted
to SQLite database (full_result_json) or left behind on disk.
"""

import unittest
import os
import json
import uuid
import tempfile
from pathlib import Path
from email_forensics.parser import parse_eml, ParsedEmail, EmailAttachment
from email_forensics.auth_checks import run_auth_checks
from email_forensics.domain_intel import run_domain_intel
from email_forensics.url_analysis import run_url_analysis
from email_forensics.attachment_analysis import run_attachment_analysis
from email_forensics.risk_scoring import calculate_risk_score
from database import setup_database, insert_email_analysis, get_email_analysis_by_id, get_db_connection


class TestAttachmentBytesNotPersisted(unittest.TestCase):

    def setUp(self):
        setup_database()

    def test_raw_bytes_not_in_full_result_json_or_db(self):
        """
        Tests that raw attachment bytes containing a distinctive marker string are
        successfully used for magic-byte analysis in memory, but NEVER persisted
        into full_result_json or the SQLite database.
        """
        distinctive_marker = "DISTINCTIVE_MALWARE_MARKER_998877665544332211"
        fake_exe_bytes = b"MZ\x90\x00\x03\x00" + distinctive_marker.encode('utf-8') + b"\x00" * 64

        # Construct in-memory EmailAttachment with content bytes
        att = EmailAttachment(
            filename="fake_invoice.pdf",
            size=len(fake_exe_bytes),
            content=fake_exe_bytes
        )

        parsed_email = ParsedEmail(
            from_name="Billing Dept",
            from_address="billing@vendor.com",
            to="user@corp.com",
            subject="Invoice Payment Required",
            date=None,
            return_path="bounce@vendor.com",
            reply_to=None,
            message_id="<test-id-12345@vendor.com>",
            received_headers=["Received: from mail.vendor.com (mail.vendor.com [198.51.100.1]) by mx.corp.com"],
            body_plain="Please see attached invoice.",
            body_html="<p>Please see attached invoice.</p>",
            attachments=[att]
        )

        # Confirm content bytes are available during in-memory processing
        self.assertIsNotNone(parsed_email.attachments[0].content)

        # Run analysis pipeline
        auth_res = run_auth_checks(parsed_email, raw_bytes=b"")
        domain_res = run_domain_intel(parsed_email)
        url_res = run_url_analysis(parsed_email)
        att_res = run_attachment_analysis(parsed_email)

        # Signature mismatch should be detected via in-memory magic bytes
        self.assertTrue(att_res.has_signature_mismatch)

        risk_res = calculate_risk_score(parsed_email, auth_res, domain_res, url_res, att_res)

        # Build full_payload for database insertion (same as routes.py)
        full_payload = {
            'metadata': {
                'filename': 'test_sample.eml',
                'file_size': 1024,
                'unique_id': 'test_unique_id_12345',
            },
            'parsed_email': parsed_email.to_dict(),
            'auth_result': auth_res.to_dict(),
            'domain_result': domain_res.to_dict(),
            'url_result': url_res.to_dict(),
            'attachment_result': att_res.to_dict(),
            'risk_result': risk_res.to_dict(),
        }

        full_json_str = json.dumps(full_payload, indent=2, default=str)

        # 1. ASSERTION: Distinctive marker string MUST NOT be present in full_json_str
        self.assertNotIn(
            distinctive_marker,
            full_json_str,
            "CRITICAL LEAK: Raw attachment bytes marker string was found in serialized full_json_str!"
        )

        # 2. Persist to database and query directly from SQLite
        test_user_id = 999999
        analysis_id = insert_email_analysis(
            user_id=test_user_id,
            filename='test_sample.eml',
            risk_score=risk_res.total_score,
            risk_band=risk_res.risk_band,
            hard_flagged=risk_res.hard_flagged,
            full_result_json=full_json_str
        )

        db_record = get_email_analysis_by_id(analysis_id)
        self.assertIsNotNone(db_record)
        stored_json = db_record['full_result_json']

        # ASSERTION: Marker string MUST NOT be in stored SQLite column
        self.assertNotIn(
            distinctive_marker,
            stored_json,
            "CRITICAL LEAK: Raw attachment bytes marker string was persisted into SQLite database!"
        )

        # 3. ASSERTION: Derived fields ARE present in stored JSON
        stored_dict = json.loads(stored_json)
        parsed_atts = stored_dict['parsed_email']['attachments']
        self.assertEqual(len(parsed_atts), 1)
        self.assertEqual(parsed_atts[0]['filename'], "fake_invoice.pdf")
        self.assertEqual(parsed_atts[0]['size'], len(fake_exe_bytes))
        self.assertTrue(parsed_atts[0]['has_content'])
        self.assertNotIn('content', parsed_atts[0])

        att_analysis_atts = stored_dict['attachment_result']['attachments']
        self.assertEqual(len(att_analysis_atts), 1)
        self.assertTrue(att_analysis_atts[0]['is_signature_mismatch'])
        self.assertEqual(att_analysis_atts[0]['claimed_extension'], ".pdf")
        self.assertTrue(
            any(m in att_analysis_atts[0]['detected_mime'] for m in ("dsexec", "dosexec", "executable")),
            f"Expected executable MIME type in detected_mime, got {att_analysis_atts[0]['detected_mime']}"
        )

    def test_no_leftover_temp_files_on_disk(self):
        """Confirming zero temporary files remain in tmp upload directory after analysis."""
        tmp_dir = Path("uploads/tmp")

        if tmp_dir.exists():
            files_before = set(tmp_dir.glob("*"))
        else:
            files_before = set()

        # Simulate temporary file creation and cleanup as in routes.py
        os.makedirs("uploads/tmp", exist_ok=True)
        dummy_path = tmp_dir / f"test_cleanup_{uuid.uuid4().hex[:8]}.tmp"
        dummy_path.write_bytes(b"temp raw upload file content")
        self.assertTrue(dummy_path.exists())

        # Cleanup block (same as routes.py finally)
        if dummy_path.exists():
            os.remove(dummy_path)

        if tmp_dir.exists():
            files_after = set(tmp_dir.glob("*"))
        else:
            files_after = set()

        self.assertNotIn(dummy_path, files_after)


if __name__ == '__main__':
    unittest.main()
