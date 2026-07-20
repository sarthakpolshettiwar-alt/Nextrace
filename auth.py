import os
import secrets
import datetime
from urllib.parse import urlencode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user, UserMixin

import database
from email_service import send_otp_email

auth_bp = Blueprint('auth', __name__)

class User(UserMixin):
    def __init__(self, id, username, email, is_verified):
        self.id = id
        self.username = username
        self.email = email
        self.is_verified = is_verified

# We'll need a user loader for Flask-Login, which we'll configure in app.py, but it uses this class

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # We assume a dashboard route exists in app.py
        
    if request.method == 'POST':
        email_or_username = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        trust_device = 'trust_device' in request.form
        
        # Check lockout
        failed_attempts = database.get_recent_failed_logins(email_or_username)
        if failed_attempts >= 5:
            flash("Too many failed attempts. Please try again in 15 minutes.", "error")
            return render_template('auth/login.html')
            
        user_row = database.get_user_by_email(email_or_username)
        if not user_row:
            user_row = database.get_user_by_username(email_or_username)
            
        ip_addr = request.remote_addr
        
        if user_row and check_password_hash(user_row['password_hash'], password):
            database.log_login_attempt(user_row['email'], True, 'password', ip_addr)
            user_obj = User(user_row['id'], user_row['username'], user_row['email'], user_row['is_verified'])
            login_user(user_obj, remember=remember)
            session.permanent = True  # Enforce 30 min timeout via app config
            
            resp = redirect(url_for('dashboard'))
            if trust_device:
                token = secrets.token_hex(32)
                expires = datetime.datetime.utcnow() + datetime.timedelta(days=30)
                database.add_trusted_device(user_row['id'], token, expires.strftime("%Y-%m-%d %H:%M:%S"))
                resp.set_cookie('trusted_device_token', token, max_age=30*24*60*60, httponly=True)
            return resp
        else:
            actual_email = user_row['email'] if user_row else email_or_username
            database.log_login_attempt(actual_email, False, 'password', ip_addr)
            flash("Invalid credentials.", "error")
            
    return render_template('auth/login.html')

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if database.get_user_by_email(email):
            flash("Email already registered.", "error")
            return redirect(url_for('auth.signup'))
            
        if database.get_user_by_username(username):
            flash("Username already taken.", "error")
            return redirect(url_for('auth.signup'))
            
        # Add basic server side validation
        if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c.isupper() for c in password):
            flash("Password does not meet complexity requirements.", "error")
            return redirect(url_for('auth.signup'))
            
        pwd_hash = generate_password_hash(password)
        database.create_user(username, email, pwd_hash, is_verified=False)
        flash("Account created successfully. Please login.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('auth/signup.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('auth.login'))

@auth_bp.route('/auth/google')
def google_auth():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return current_app.oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/auth/google/callback')
def google_callback():
    token = current_app.oauth.google.authorize_access_token()
    user_info = current_app.oauth.google.get('userinfo').json()
    
    email = user_info.get('email')
    username = user_info.get('name', email.split('@')[0])
    
    ip_addr = request.remote_addr
    
    user_row = database.get_user_by_email(email)
    if not user_row:
        # Auto-create user
        pwd_hash = generate_password_hash(secrets.token_urlsafe(32))
        database.create_user(username, email, pwd_hash, is_verified=True)
        user_row = database.get_user_by_email(email)
        
    database.log_login_attempt(email, True, 'google', ip_addr)
    user_obj = User(user_row['id'], user_row['username'], user_row['email'], user_row['is_verified'])
    login_user(user_obj)
    session.permanent = True
    
    return redirect(url_for('dashboard'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Rate limit
        count = database.get_otp_requests_count_last_hour(email)
        if count >= 3:
            flash("Too many requests. Try again later.", "error")
            return render_template('auth/forgot_password.html')
            
        user_row = database.get_user_by_email(email)
        if user_row:
            otp = "".join([str(secrets.randbelow(10)) for _ in range(6)])
            expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
            database.save_otp(email, otp, expires.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Send Email
            success = send_otp_email(email, otp)
            if success:
                session['reset_email'] = email
                return redirect(url_for('auth.verify_otp'))
            else:
                flash("Failed to send email. Check configuration.", "error")
        else:
            # Don't leak existence, just act like it worked
            session['reset_email'] = email
            return redirect(url_for('auth.verify_otp'))
            
    return render_template('auth/forgot_password.html')

@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('auth.forgot_password'))
        
    if request.method == 'POST':
        code = request.form.get('otp_code')
        otp_record = database.get_valid_otp(email)
        
        if not otp_record:
            flash("No valid OTP found or it has expired.", "error")
            return redirect(url_for('auth.forgot_password'))
            
        if otp_record['attempts'] >= 5:
            flash("Too many failed attempts. Request a new OTP.", "error")
            database.mark_otp_used(otp_record['id'])
            return redirect(url_for('auth.forgot_password'))
            
        if otp_record['otp_code'] == code:
            database.mark_otp_used(otp_record['id'])
            session['otp_verified'] = True
            return redirect(url_for('auth.reset_password'))
        else:
            database.increment_otp_attempts(otp_record['id'])
            flash("Invalid OTP.", "error")
            
    return render_template('auth/verify_otp.html')

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email or not session.get('otp_verified'):
        return redirect(url_for('auth.forgot_password'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c.isupper() for c in password):
            flash("Password does not meet complexity requirements.", "error")
            return render_template('auth/reset_password.html')
            
        pwd_hash = generate_password_hash(password)
        database.update_user_password(email, pwd_hash)
        
        session.pop('reset_email', None)
        session.pop('otp_verified', None)
        flash("Password reset successfully. Please login.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('auth/reset_password.html')

@auth_bp.route('/activity_log')
@login_required
def activity_log():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    records, total = database.get_paginated_activity_log(page=page, per_page=25, search_email=search)
    
    total_pages = (total + 24) // 25
    return render_template('auth/activity_log.html', records=records, page=page, total_pages=total_pages, search=search)
