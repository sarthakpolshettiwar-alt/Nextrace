import unittest
import os
import sqlite3
import io
from app import app
import database
from werkzeug.security import generate_password_hash, check_password_hash

class TestSettingsPage(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with app.app_context():
            database.setup_database()
        
        # Cleanup test user if exists
        conn = database.get_db_connection()
        conn.execute("DELETE FROM User WHERE email = 'settings_test@example.com'")
        conn.execute("DELETE FROM User WHERE email = 'google_test@example.com'")
        conn.commit()
        conn.close()

    def test_01_settings_route_protected(self):
        """1. Protected route: redirect unauthenticated user to /login"""
        response = self.client.get('/settings', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)

    def test_02_profile_update_and_avatar_upload(self):
        """2. Profile Settings: update username and upload profile picture to static/uploads/profile_pictures/"""
        # Create test user
        user_id = database.create_user('settingstestuser', 'settings_test@example.com', generate_password_hash('Password123!'))

        # Log in
        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})

        # Update profile
        data = {
            'username': 'updated_settingstestuser',
            'profile_picture': (io.BytesIO(b"fake image content"), 'avatar.png')
        }
        response = self.client.post('/settings/profile', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Check DB
        updated_user = database.get_user_by_id(user_id)
        self.assertEqual(updated_user['username'], 'updated_settingstestuser')
        self.assertIsNotNone(updated_user['profile_picture'])
        self.assertTrue(updated_user['profile_picture'].startswith('uploads/profile_pictures/'))

        # Check file exists on filesystem
        full_path = os.path.join(app.static_folder, updated_user['profile_picture'])
        self.assertTrue(os.path.exists(full_path))

        # Cleanup created image file
        if os.path.exists(full_path):
            os.remove(full_path)

    def test_03_password_change_and_google_autohide(self):
        """3. Password Change & Google-only autohide"""
        # Create standard password user
        user_id = database.create_user('pwduser', 'settings_test@example.com', generate_password_hash('Password123!'))
        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})

        # Render settings page -> Password section present
        resp = self.client.get('/settings')
        self.assertIn('Password Management', resp.get_data(as_text=True))

        # Incorrect current password
        resp = self.client.post('/settings/password', data={
            'current_password': 'WrongPassword123!',
            'new_password': 'NewPassword123!',
            'confirm_password': 'NewPassword123!'
        }, follow_redirects=True)
        self.assertIn('Current password is incorrect', resp.get_data(as_text=True))

        # Valid password change
        resp = self.client.post('/settings/password', data={
            'current_password': 'Password123!',
            'new_password': 'NewPassword456!',
            'confirm_password': 'NewPassword456!'
        }, follow_redirects=True)
        self.assertIn('Password updated successfully', resp.get_data(as_text=True))

        # Verify new password in DB
        updated_user = database.get_user_by_id(user_id)
        self.assertTrue(check_password_hash(updated_user['password_hash'], 'NewPassword456!'))

        # Create Google-only user
        g_user_id = database.create_user('googleuser', 'google_test@example.com', 'oauth_google')
        self.client.get('/auth/logout')

        # Log in as google user using test_client session or direct login setup
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(g_user_id)

        resp = self.client.get('/settings')
        self.assertNotIn('Password Management', resp.get_data(as_text=True))

    def test_04_security_and_sessions(self):
        """4. Security & Sessions: display, remove device, sign out all devices"""
        user_id = database.create_user('devuser', 'settings_test@example.com', generate_password_hash('Password123!'))
        database.add_trusted_device(user_id, 'token_123', '2099-01-01 00:00:00')
        devices = database.get_user_trusted_devices(user_id)
        self.assertEqual(len(devices), 1)

        device_id = devices[0]['id']

        # Log in
        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})

        # Remove single device
        resp = self.client.post(f'/settings/devices/remove/{device_id}', follow_redirects=True)
        self.assertIn('Trusted device removed', resp.get_data(as_text=True))
        self.assertEqual(len(database.get_user_trusted_devices(user_id)), 0)

        # Add device and revoke all
        database.add_trusted_device(user_id, 'token_456', '2099-01-01 00:00:00')
        resp = self.client.post('/settings/devices/revoke-all', follow_redirects=True)
        self.assertIn('All trusted devices signed out', resp.get_data(as_text=True))
        self.assertEqual(len(database.get_user_trusted_devices(user_id)), 0)

    def test_05_notification_preferences(self):
        """5. Notification preferences toggle"""
        user_id = database.create_user('notifyuser', 'settings_test@example.com', generate_password_hash('Password123!'))
        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})

        # Toggle off
        resp = self.client.post('/settings/notifications', data={}, follow_redirects=True)
        user = database.get_user_by_id(user_id)
        self.assertEqual(user['notify_analysis_complete'], 0)

        # Toggle on
        resp = self.client.post('/settings/notifications', data={'notify_analysis_complete': 'on'}, follow_redirects=True)
        user = database.get_user_by_id(user_id)
        self.assertEqual(user['notify_analysis_complete'], 1)

    def test_06_danger_zone_account_deletion(self):
        """6. Danger Zone account deletion with exact email confirmation"""
        user_id = database.create_user('deluser', 'settings_test@example.com', generate_password_hash('Password123!'))
        database.add_trusted_device(user_id, 'token_del', '2099-01-01 00:00:00')

        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})

        # Wrong email confirmation
        resp = self.client.post('/settings/delete-account', data={'confirm_email': 'wrong@example.com'}, follow_redirects=True)
        self.assertIn('confirmation does not match', resp.get_data(as_text=True))
        self.assertIsNotNone(database.get_user_by_id(user_id))

        # Correct email confirmation
        resp = self.client.post('/settings/delete-account', data={'confirm_email': 'settings_test@example.com'}, follow_redirects=True)
        self.assertIn('permanently deleted', resp.get_data(as_text=True))
        self.assertIsNone(database.get_user_by_id(user_id))
        self.assertEqual(len(database.get_user_trusted_devices(user_id)), 0)

    def test_07_sidebar_navigation_settings_link(self):
        """7. Sidebar navigation Settings link"""
        database.create_user('navuser', 'settings_test@example.com', generate_password_hash('Password123!'))
        self.client.post('/login', data={'email': 'settings_test@example.com', 'password': 'Password123!'})
        resp = self.client.get('/dashboard')
        self.assertIn('/settings', resp.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
