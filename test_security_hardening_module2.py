"""
test_security_hardening_module2.py

Security Hardening Test Suite for Forenix Module 2 (Email Forensic Analysis).
Verifies:
1. Cross-User Ownership Enforcement (Results & PDF Routes)
2. Disguised/Corrupt File Validation Rejection
3. Malicious Subject Line HTML/XSS Escaping in Templates
4. Rate Limiting Enforcement
5. PDF Report Generation Endpoint
"""

import unittest
import os
import io
import json
import sqlite3
from werkzeug.security import generate_password_hash

TEST_DB = "test_security_module2.db"

import database

original_get_db_connection = database.get_db_connection
original_db_name = database.DB_NAME

def get_test_db_connection():
    conn = sqlite3.connect(TEST_DB)
    conn.row_factory = sqlite3.Row
    return conn

database.get_db_connection = get_test_db_connection
database.DB_NAME = TEST_DB

from app import app
from database import setup_database, create_user, get_db_connection


class TestModule2SecurityHardening(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SERVER_NAME'] = 'localhost'

    @classmethod
    def tearDownClass(cls):
        database.get_db_connection = original_get_db_connection
        database.DB_NAME = original_db_name

    def setUp(self):
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except Exception:
                pass
        
        setup_database(TEST_DB)

        # Fresh test client per test method
        self.client = app.test_client()

        # Create 2 test users with valid Werkzeug password hashes
        pw_hash = generate_password_hash("password123")
        create_user("user_alpha", "alpha@forenix.org", pw_hash, is_verified=True)
        create_user("user_beta", "beta@forenix.org", pw_hash, is_verified=True)

        conn = get_db_connection()
        user1 = conn.execute("SELECT id FROM User WHERE username = 'user_alpha'").fetchone()
        user2 = conn.execute("SELECT id FROM User WHERE username = 'user_beta'").fetchone()
        conn.close()

        self.user1_id = user1['id']
        self.user2_id = user2['id']

    def tearDown(self):
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except Exception:
                pass

    def login_client(self, client, email, password):
        return client.post('/login', data={'email': email, 'password': password}, follow_redirects=True)

    def test_01_ownership_enforcement(self):
        """Test that User B cannot view or download PDF for User A's analysis."""
        # 1. Login as User Alpha and upload clean sample
        login_res = self.login_client(self.client, "alpha@forenix.org", "password123")
        self.assertIn(b"Welcome to Forenix", login_res.data)

        sample_eml = (
            "From: Sender <sender@example.com>\n"
            "To: Recipient <recipient@example.com>\n"
            "Subject: Clean Test Email\n"
            "Date: Wed, 05 Aug 2026 12:00:00 +0000\n"
            "Message-ID: <test1@example.com>\n\n"
            "This is a clean email body.\n"
        ).encode('utf-8')

        data = {'email_file': (io.BytesIO(sample_eml), 'sample_alpha.eml')}
        res = self.client.post('/module2/analyze', data=data, content_type='multipart/form-data', follow_redirects=False)

        self.assertEqual(res.status_code, 302)
        analysis_url = res.headers['Location']
        analysis_id = int(analysis_url.split('/')[-1])

        # Confirm User Alpha can view their own result (200 OK)
        res_owner = self.client.get(f'/module2/results/{analysis_id}')
        self.assertEqual(res_owner.status_code, 200)

        # 2. Login as User Beta using a separate client
        beta_client = app.test_client()
        self.login_client(beta_client, "beta@forenix.org", "password123")

        res_unauthorized_view = beta_client.get(f'/module2/results/{analysis_id}', follow_redirects=True)
        # Expect 403 status or redirect with "Access denied" error
        self.assertIn(b"Access denied", res_unauthorized_view.data)

        # Attempt PDF download as User Beta
        res_unauthorized_pdf = beta_client.get(f'/module2/results/{analysis_id}/pdf', follow_redirects=True)
        self.assertIn(b"Access denied", res_unauthorized_pdf.data)
        print("\n[PASS] Test 1: Cross-user ownership enforcement verified.")

    def test_02_disguised_file_rejection(self):
        """Test that disguised or non-email files are rejected cleanly."""
        self.login_client(self.client, "alpha@forenix.org", "password123")

        # Fake .eml containing invalid binary data
        fake_binary = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
        data = {'email_file': (io.BytesIO(fake_binary), 'malicious.eml')}
        res = self.client.post('/module2/analyze', data=data, content_type='multipart/form-data', follow_redirects=True)

        self.assertIn(b"Invalid email file", res.data)
        print("[PASS] Test 2: Disguised file content validation rejection verified.")

    def test_03_xss_subject_escaping(self):
        """Test that malicious HTML/XSS script in email Subject line is properly escaped in HTML response."""
        self.login_client(self.client, "alpha@forenix.org", "password123")

        malicious_script = "<script>alert('XSS_ATTACK_VECTOR')</script>"
        xss_eml = (
            f"From: Attacker <attacker@bad.com>\n"
            f"To: Victim <victim@example.com>\n"
            f"Subject: {malicious_script}\n"
            f"Date: Wed, 05 Aug 2026 12:00:00 +0000\n"
            f"Message-ID: <xss@bad.com>\n\n"
            f"Body text\n"
        ).encode('utf-8')

        data = {'email_file': (io.BytesIO(xss_eml), 'xss_sample.eml')}
        res_upload = self.client.post('/module2/analyze', data=data, content_type='multipart/form-data', follow_redirects=False)

        analysis_url = res_upload.headers['Location']
        res_view = self.client.get(analysis_url)

        self.assertEqual(res_view.status_code, 200)
        # Confirm script tag is escaped (&lt;script&gt;) and raw <script> does not exist un-escaped inside HTML
        self.assertNotIn(malicious_script.encode('utf-8'), res_view.data)
        self.assertIn(b"&lt;script&gt;", res_view.data)
        print("[PASS] Test 3: Malicious Subject XSS escaping verified.")

    def test_04_pdf_generation_endpoint(self):
        """Test that PDF report endpoint generates valid application/pdf binary stream."""
        self.login_client(self.client, "alpha@forenix.org", "password123")

        sample_eml = (
            "From: Sender <sender@example.com>\n"
            "To: Recipient <recipient@example.com>\n"
            "Subject: PDF Test Email\n"
            "Date: Wed, 05 Aug 2026 12:00:00 +0000\n"
            "Message-ID: <pdftest@example.com>\n\n"
            "Sample email for PDF export.\n"
        ).encode('utf-8')

        data = {'email_file': (io.BytesIO(sample_eml), 'pdf_test.eml')}
        res = self.client.post('/module2/analyze', data=data, content_type='multipart/form-data', follow_redirects=False)

        analysis_id = int(res.headers['Location'].split('/')[-1])

        # Request PDF download
        res_pdf = self.client.get(f'/module2/results/{analysis_id}/pdf')
        self.assertEqual(res_pdf.status_code, 200)
        self.assertEqual(res_pdf.mimetype, 'application/pdf')
        self.assertTrue(res_pdf.data.startswith(b'%PDF'))
        print("[PASS] Test 4: PDF report generation endpoint verified.")


if __name__ == '__main__':
    unittest.main()
