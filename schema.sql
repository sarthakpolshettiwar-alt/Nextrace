CREATE TABLE IF NOT EXISTS USB_Device (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_hive TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    revision TEXT,
    serial_number TEXT NOT NULL,
    friendly_name TEXT,
    parent_id_prefix TEXT,
    last_write_time DATETIME,
    UNIQUE(serial_number, source_hive)
);

CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_verified BOOLEAN DEFAULT 0,
    profile_picture TEXT,
    notify_analysis_complete BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS Login_Attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    method TEXT NOT NULL, -- 'password' or 'google'
    ip_address TEXT
);

CREATE TABLE IF NOT EXISTS PasswordReset (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS TrustedDevices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_token TEXT NOT NULL,
    device_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id) REFERENCES User(id)
);

CREATE TABLE IF NOT EXISTS email_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER NOT NULL,
    risk_band TEXT NOT NULL,
    hard_flagged BOOLEAN NOT NULL DEFAULT 0,
    full_result_json TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES User(id)
);




