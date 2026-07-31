import os
import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import database

settings_bp = Blueprint('settings', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@settings_bp.route('/settings', methods=['GET'])
@login_required
def view_settings():
    trusted_devices = database.get_user_trusted_devices(current_user.id)
    return render_template('settings.html', trusted_devices=trusted_devices)

@settings_bp.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username', '').strip()
    
    if not username:
        flash("Username cannot be empty.", "error")
        return redirect(url_for('settings.view_settings'))
        
    if username != current_user.username:
        existing = database.get_user_by_username(username)
        if existing and existing['id'] != current_user.id:
            flash("Username is already taken.", "error")
            return redirect(url_for('settings.view_settings'))
            
    profile_picture_rel_path = None
    file = request.files.get('profile_picture')
    if file and file.filename != '':
        if allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            safe_filename = f"avatar_{current_user.id}_{secrets.token_hex(8)}.{ext}"
            upload_dir = os.path.join(current_app.static_folder, 'uploads', 'profile_pictures')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, safe_filename)
            file.save(file_path)
            profile_picture_rel_path = f"uploads/profile_pictures/{safe_filename}"
        else:
            flash("Invalid image format. Allowed: PNG, JPG, JPEG, GIF, WEBP.", "error")
            return redirect(url_for('settings.view_settings'))
            
    database.update_user_profile(current_user.id, username, profile_picture_rel_path)
    flash("Profile updated successfully.", "success")
    return redirect(url_for('settings.view_settings'))

@settings_bp.route('/settings/password', methods=['POST'])
@login_required
def update_password():
    if not current_user.has_password:
        flash("Password changes are disabled for Google accounts.", "error")
        return redirect(url_for('settings.view_settings'))
        
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Fetch full user row to get current password hash
    user_row = database.get_user_by_id(current_user.id)
    if not user_row or not check_password_hash(user_row['password_hash'], current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for('settings.view_settings'))
        
    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for('settings.view_settings'))
        
    if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isupper() for c in new_password):
        flash("New password must be at least 8 characters long and contain at least 1 uppercase letter and 1 number.", "error")
        return redirect(url_for('settings.view_settings'))
        
    pwd_hash = generate_password_hash(new_password)
    database.update_user_password_by_id(current_user.id, pwd_hash)
    flash("Password updated successfully.", "success")
    return redirect(url_for('settings.view_settings'))

@settings_bp.route('/settings/devices/remove/<int:device_id>', methods=['POST'])
@login_required
def remove_device(device_id):
    database.remove_trusted_device(device_id, current_user.id)
    flash("Trusted device removed.", "success")
    return redirect(url_for('settings.view_settings'))

@settings_bp.route('/settings/devices/revoke-all', methods=['POST'])
@login_required
def revoke_all_devices():
    database.remove_all_trusted_devices(current_user.id)
    logout_user()
    session.clear()
    flash("All trusted devices signed out. Please sign in again.", "success")
    return redirect(url_for('auth.login'))

@settings_bp.route('/settings/notifications', methods=['POST'])
@login_required
def update_notifications():
    notify = 'notify_analysis_complete' in request.form
    database.update_user_notification_prefs(current_user.id, notify)
    flash("Notification preferences saved.", "success")
    return redirect(url_for('settings.view_settings'))

@settings_bp.route('/settings/delete-account', methods=['POST'])
@login_required
def delete_account():
    confirm_email = request.form.get('confirm_email', '').strip()
    
    if confirm_email.lower() != current_user.email.lower():
        flash("Email address confirmation does not match.", "error")
        return redirect(url_for('settings.view_settings'))
        
    user_id = current_user.id
    email = current_user.email
    logout_user()
    session.clear()
    database.delete_user_account(user_id, email)
    flash("Your account and all associated data have been permanently deleted.", "success")
    return redirect(url_for('auth.login'))
