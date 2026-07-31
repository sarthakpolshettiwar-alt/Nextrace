import unittest
import os
import sqlite3
import datetime
from app import app
import database
from werkzeug.security import generate_password_hash

class TestLoginRateLimit(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with app.app_context():
            database.setup_database()

        self.test_email = 'ratelimit_user@example.com'
        self.test_username = 'ratelimituser'
        self.test_password = 'Password123!'

        # Clean up existing test data
        conn = database.get_db_connection()
        conn.execute("DELETE FROM User WHERE email = ?", (self.test_email,))
        conn.execute("DELETE FROM Login_Attempts WHERE email = ?", (self.test_email,))
        conn.commit()
        conn.close()

        # Create user
        self.user_id = database.create_user(
            self.test_username,
            self.test_email,
            generate_password_hash(self.test_password)
        )

    def tearDown(self):
        conn = database.get_db_connection()
        conn.execute("DELETE FROM User WHERE email = ?", (self.test_email,))
        conn.execute("DELETE FROM Login_Attempts WHERE email = ?", (self.test_email,))
        conn.commit()
        conn.close()

    def test_login_rate_limiting_5_failed_attempts(self):
        """
        Test that 5 failed login attempts trigger lockout on the 6th attempt,
        even with valid password.
        """
        # Fail 5 login attempts in a row
        for i in range(5):
            resp = self.client.post('/login', data={
                'email': self.test_email,
                'password': 'WrongPassword!'
            }, follow_redirects=True)
            self.assertIn("Invalid credentials.", resp.get_data(as_text=True))

        # Check total logged attempts in DB (should be 5 failed attempts)
        conn = database.get_db_connection()
        count = conn.execute("SELECT COUNT(*) FROM Login_Attempts WHERE email = ? AND success = 0", (self.test_email,)).fetchone()[0]
        conn.close()
        self.assertEqual(count, 5)

        # 6th attempt with INVALID password - should be blocked immediately with remaining time
        resp_6th_invalid = self.client.post('/login', data={
            'email': self.test_email,
            'password': 'WrongPassword!'
        }, follow_redirects=True)
        body = resp_6th_invalid.get_data(as_text=True)
        self.assertIn("Too many failed attempts. Please try again in", body)

        # 6th attempt with VALID password - should STILL be blocked immediately
        resp_6th_valid = self.client.post('/login', data={
            'email': self.test_email,
            'password': self.test_password
        }, follow_redirects=True)
        body_valid = resp_6th_valid.get_data(as_text=True)
        self.assertIn("Too many failed attempts. Please try again in", body_valid)

    def test_login_rate_limiting_with_username(self):
        """
        Test rate limiting when logging in using username instead of email.
        """
        for i in range(5):
            self.client.post('/login', data={
                'email': self.test_username,
                'password': 'WrongPassword!'
            }, follow_redirects=True)

        # 6th attempt using username should be blocked
        resp = self.client.post('/login', data={
            'email': self.test_username,
            'password': self.test_password
        }, follow_redirects=True)
        self.assertIn("Too many failed attempts. Please try again in", resp.get_data(as_text=True))

    def test_successful_login_does_not_delete_attempts(self):
        """
        Verify that past failed attempts are not deleted/cleared upon successful login.
        """
        # Log 2 failed attempts
        for i in range(2):
            self.client.post('/login', data={'email': self.test_email, 'password': 'Wrong!'})

        # Successful login
        self.client.post('/login', data={'email': self.test_email, 'password': self.test_password})

        # Verify failed attempts still exist in DB (not cleared)
        conn = database.get_db_connection()
        failed_count = conn.execute("SELECT COUNT(*) FROM Login_Attempts WHERE email = ? AND success = 0", (self.test_email,)).fetchone()[0]
        conn.close()
        self.assertEqual(failed_count, 2)

if __name__ == '__main__':
    unittest.main()
