import sqlite3
import os
import datetime
import math
from typing import List
from usbstor_parser import UsbDevice

DB_NAME = "usb_forensics.db"
SCHEMA_FILE = "schema.sql"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database(db_path: str = DB_NAME):
    """Initialize the database with the schema and run migrations."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if os.path.exists(SCHEMA_FILE):
        with open(SCHEMA_FILE, "r") as f:
            cursor.executescript(f.read())
    else:
        raise FileNotFoundError(f"Schema file not found: {SCHEMA_FILE}")
        
    # Check for missing columns in User table for existing DBs
    cursor.execute("PRAGMA table_info(User)")
    columns = [col[1] for col in cursor.fetchall()]
    if "profile_picture" not in columns:
        cursor.execute("ALTER TABLE User ADD COLUMN profile_picture TEXT")
    if "notify_analysis_complete" not in columns:
        cursor.execute("ALTER TABLE User ADD COLUMN notify_analysis_complete BOOLEAN DEFAULT 1")

    conn.commit()
    conn.close()

def insert_usb_devices(devices: List[UsbDevice], source_hive: str, db_path: str = DB_NAME):
    """
    Insert a list of UsbDevice objects into the database.
    If the serial number already exists, update its last_write_time.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    for device in devices:
        cursor.execute("SELECT id FROM USB_Device WHERE serial_number = ? AND source_hive = ?", (device.serial_number, source_hive))
        result = cursor.fetchone()
        
        if result:
            cursor.execute("""
                UPDATE USB_Device 
                SET last_write_time = ?
                WHERE serial_number = ? AND source_hive = ?
            """, (device.last_write_time, device.serial_number, source_hive))
        else:
            cursor.execute("""
                INSERT INTO USB_Device (
                    source_hive, vendor, product, revision, serial_number, 
                    friendly_name, parent_id_prefix, last_write_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source_hive, device.vendor, device.product, device.revision,
                device.serial_number, device.friendly_name, device.parent_id_prefix,
                device.last_write_time
            ))
            
    conn.commit()
    conn.close()

def get_all_devices(db_path: str = DB_NAME):
    """Retrieve all stored USB devices from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM USB_Device")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# --- Auth Helper Functions ---

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE email = ?', (email,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM User WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(user) if user else None

def create_user(username, email, password_hash, is_verified=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO User (username, email, password_hash, is_verified) VALUES (?, ?, ?, ?)',
                   (username, email, password_hash, is_verified))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id

def log_login_attempt(email, success, method, ip_address):
    conn = get_db_connection()
    conn.execute('INSERT INTO Login_Attempts (email, success, method, ip_address) VALUES (?, ?, ?, ?)',
                 (email, success, method, ip_address))
    conn.commit()
    conn.close()

def get_recent_failed_logins(email, minutes=15):
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM Login_Attempts 
        WHERE email = ? AND success = 0 
        AND timestamp >= datetime('now', ?)
    ''', (email, f'-{minutes} minutes')).fetchone()[0]
    conn.close()
    return count

def get_login_lockout_info(email, max_attempts=5, window_minutes=15):
    if not email:
        return False, 0, 0
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT timestamp FROM Login_Attempts 
        WHERE email = ? AND success = 0 
        AND timestamp >= datetime('now', ?)
        ORDER BY timestamp ASC
    ''', (email, f'-{window_minutes} minutes')).fetchall()
    conn.close()

    count = len(rows)
    if count < max_attempts:
        return False, 0, count

    target_row = rows[count - max_attempts]
    ts_str = target_row['timestamp'] if isinstance(target_row, sqlite3.Row) else target_row[0]

    try:
        attempt_time = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        try:
            attempt_time = datetime.datetime.fromisoformat(str(ts_str).replace('Z', ''))
        except Exception:
            attempt_time = datetime.datetime.utcnow()

    unlock_time = attempt_time + datetime.timedelta(minutes=window_minutes)
    now_utc = datetime.datetime.utcnow()

    remaining_seconds = (unlock_time - now_utc).total_seconds()
    remaining_minutes = math.ceil(remaining_seconds / 60)
    if remaining_minutes <= 0:
        remaining_minutes = 1

    return True, remaining_minutes, count

def add_trusted_device(user_id, device_token, expires_at):
    conn = get_db_connection()
    conn.execute('INSERT INTO TrustedDevices (user_id, device_token, expires_at) VALUES (?, ?, ?)',
                 (user_id, device_token, expires_at))
    conn.commit()
    conn.close()

def is_trusted_device(user_id, device_token):
    conn = get_db_connection()
    device = conn.execute('''
        SELECT * FROM TrustedDevices 
        WHERE user_id = ? AND device_token = ? AND expires_at > datetime('now')
    ''', (user_id, device_token)).fetchone()
    conn.close()
    return bool(device)

def save_otp(email, otp_code, expires_at):
    conn = get_db_connection()
    conn.execute('INSERT INTO PasswordReset (email, otp_code, expires_at) VALUES (?, ?, ?)',
                 (email, otp_code, expires_at))
    conn.commit()
    conn.close()

def get_valid_otp(email):
    conn = get_db_connection()
    otp = conn.execute('''
        SELECT * FROM PasswordReset 
        WHERE email = ? AND used = 0 AND expires_at > datetime('now')
        ORDER BY created_at DESC LIMIT 1
    ''', (email,)).fetchone()
    conn.close()
    return dict(otp) if otp else None

def increment_otp_attempts(otp_id):
    conn = get_db_connection()
    conn.execute('UPDATE PasswordReset SET attempts = attempts + 1 WHERE id = ?', (otp_id,))
    conn.commit()
    conn.close()

def mark_otp_used(otp_id):
    conn = get_db_connection()
    conn.execute('UPDATE PasswordReset SET used = 1 WHERE id = ?', (otp_id,))
    conn.commit()
    conn.close()

def update_user_password(email, password_hash):
    conn = get_db_connection()
    conn.execute('UPDATE User SET password_hash = ? WHERE email = ?', (password_hash, email))
    conn.commit()
    conn.close()

def get_otp_requests_count_last_hour(email):
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM PasswordReset 
        WHERE email = ? AND created_at >= datetime('now', '-1 hour')
    ''', (email,)).fetchone()[0]
    conn.close()
    return count

def get_paginated_activity_log(page=1, per_page=25, search_email=None):
    conn = get_db_connection()
    offset = (page - 1) * per_page
    query = 'SELECT * FROM Login_Attempts'
    params = []
    
    if search_email:
        query += ' WHERE email LIKE ?'
        params.append(f'%{search_email}%')
        
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    rows = conn.execute(query, tuple(params)).fetchall()
    
    # Get total count
    count_query = 'SELECT COUNT(*) FROM Login_Attempts'
    count_params = []
    if search_email:
        count_query += ' WHERE email LIKE ?'
        count_params.append(f'%{search_email}%')
    total = conn.execute(count_query, tuple(count_params)).fetchone()[0]
    
    conn.close()
    return [dict(row) for row in rows], total

# --- Settings Helper Functions ---

def update_user_profile(user_id, username, profile_picture=None):
    conn = get_db_connection()
    if profile_picture is not None:
        conn.execute('UPDATE User SET username = ?, profile_picture = ? WHERE id = ?',
                     (username, profile_picture, user_id))
    else:
        conn.execute('UPDATE User SET username = ? WHERE id = ?',
                     (username, user_id))
    conn.commit()
    conn.close()

def update_user_password_by_id(user_id, password_hash):
    conn = get_db_connection()
    conn.execute('UPDATE User SET password_hash = ? WHERE id = ?', (password_hash, user_id))
    conn.commit()
    conn.close()

def update_user_notification_prefs(user_id, notify_analysis_complete):
    conn = get_db_connection()
    conn.execute('UPDATE User SET notify_analysis_complete = ? WHERE id = ?',
                 (1 if notify_analysis_complete else 0, user_id))
    conn.commit()
    conn.close()

def get_user_trusted_devices(user_id):
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT * FROM TrustedDevices 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def remove_trusted_device(device_id, user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM TrustedDevices WHERE id = ? AND user_id = ?', (device_id, user_id))
    conn.commit()
    conn.close()

def remove_all_trusted_devices(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM TrustedDevices WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def delete_user_account(user_id, email):
    conn = get_db_connection()
    conn.execute('DELETE FROM TrustedDevices WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM Login_Attempts WHERE email = ?', (email,))
    conn.execute('DELETE FROM PasswordReset WHERE email = ?', (email,))
    conn.execute('DELETE FROM User WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

