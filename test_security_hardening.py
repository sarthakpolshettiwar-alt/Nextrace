import unittest
import os
import io
import sqlite3
from app import app, validate_file_signature
import database
from werkzeug.security import generate_password_hash

class TestSecurityHardening(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with app.app_context():
            database.setup_database()
        
        # Cleanup test user if exists
        conn = database.get_db_connection()
        conn.execute("DELETE FROM User WHERE email = 'sectest@example.com'")
        conn.commit()
        conn.close()

        # Create & log in test user
        self.user_id = database.create_user('secuser', 'sectest@example.com', generate_password_hash('Password123!'))
        self.client.post('/login', data={'email': 'sectest@example.com', 'password': 'Password123!'})

    def test_01_magic_bytes_validation(self):
        """Item 1: Validate file magic bytes (regf for hives, ElfFile for evtx)"""
        fake_hive = (io.BytesIO(b"NOT A HIVE FILE CONTENT"), 'invalid.hive')
        fake_evtx = (io.BytesIO(b"NOT AN EVTX FILE CONTENT"), 'invalid.evtx')

        # Upload invalid hive
        resp = self.client.post('/usb-forensic', data={'system_hive': fake_hive}, follow_redirects=True)
        self.assertIn("valid registry hive file", resp.get_data(as_text=True))

        # Upload valid hive signature but invalid EVTX
        valid_hive = (io.BytesIO(b"regf" + b"\x00" * 100), 'system.hive')
        resp = self.client.post('/usb-forensic', data={
            'system_hive': valid_hive,
            'config_log': fake_evtx
        }, follow_redirects=True)
        self.assertIn("valid EVTX event log file", resp.get_data(as_text=True))

    def test_02_path_traversal_sanitization_and_cleanup(self):
        """Item 1 & 2: Path traversal filename sanitization & disk cleanup"""
        malicious_filename = "../../evil_hive.hive"
        fake_hive = (io.BytesIO(b"regf" + b"\x00" * 100), malicious_filename)

        resp = self.client.post('/usb-forensic', data={'system_hive': fake_hive}, follow_redirects=True)
        
        # Check no evil file was created outside upload directory
        self.assertFalse(os.path.exists("../../evil_hive.hive"))

        # Verify tmp folder has no leftover files
        tmp_dir = app.config['UPLOAD_FOLDER']
        if os.path.exists(tmp_dir):
            files = [f for f in os.listdir(tmp_dir) if f.endswith('.hive') or f.endswith('.evtx')]
            self.assertEqual(len(files), 0)

    def test_03_security_response_headers(self):
        """Item 3: Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)"""
        for route in ['/login', '/dashboard', '/usb-forensic', '/settings']:
            resp = self.client.get(route)
            headers = resp.headers
            self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
            self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
            self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
            csp = headers.get('Content-Security-Policy', '')
            self.assertIn("default-src 'self'", csp)
            self.assertIn("https://cdn.tailwindcss.com", csp)
            self.assertIn("https://unpkg.com", csp)

    def test_04_session_cookie_security_config(self):
        """Item 4: Session cookie security attributes"""
        self.assertTrue(app.config['SESSION_COOKIE_HTTPONLY'])
        self.assertEqual(app.config['SESSION_COOKIE_SAMESITE'], 'Lax')

    def test_05_upload_rate_limiting(self):
        """Item 5: Upload endpoint rate limiting (10 per hour)"""
        fake_hive = lambda: (io.BytesIO(b"regf" + b"\x00" * 100), 'system.hive')
        
        limit_triggered = False
        for i in range(12):
            resp = self.client.post('/usb-forensic', data={'system_hive': fake_hive()}, follow_redirects=True)
            body = resp.get_data(as_text=True)
            if "reached the upload limit" in body or resp.status_code == 429:
                limit_triggered = True
                break

        self.assertTrue(limit_triggered, "Rate limiting should be triggered after exceeding 10 uploads")

if __name__ == '__main__':
    unittest.main()
