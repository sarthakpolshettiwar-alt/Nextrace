import os
from datetime import timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import setup_database, get_user_by_id, insert_usb_devices, get_all_devices
from auth import auth_bp, User
from settings import settings_bp
from regripper_runner import run_regripper
from usbstor_parser import parse_usbstor_output
from tools.event_parser import parse_usb_events, correlate_events_with_devices, analyze_risk
from tools.report_generator import generate_pdf_report
from tools.session_correlator import UsbSessionCorrelator
from tools.analytics_service import UsbAnalyticsService
from tools.session_repository import UsbSession

import logging

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Security Cookie Config
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
is_production = os.environ.get('IS_PRODUCTION', 'False').lower() in ('true', '1', 't') or os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = is_production

# Max File Size Limit (100MB)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Isolated Temporary Upload Folder outside static web root
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads', 'tmp')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Rate Limiter
def get_limiter_key():
    if current_user and current_user.is_authenticated:
        return str(current_user.id)
    return get_remote_address()

limiter = Limiter(
    key_func=get_limiter_key,
    app=app,
    storage_uri="memory://"
)

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("You've reached the upload limit. Please try again later.", "error")
    return redirect(url_for('usb_forensic'))

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def request_entity_too_large(e):
    flash("File size exceeds maximum limit of 100MB.", "error")
    return redirect(url_for('usb_forensic'))

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Init CSRF
csrf = CSRFProtect(app)

# Init LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'error'

@login_manager.user_loader
def load_user(user_id):
    user_row = get_user_by_id(user_id)
    if user_row:
        return User.from_row(user_row)
    return None

# Init OAuth
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Pass oauth to app context for blueprint
app.oauth = oauth

from email_forensics import email_bp

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(email_bp)

# Apply Rate Limiter to Module 2 upload endpoint
limiter.limit("10 per hour", methods=['POST'])(app.view_functions['email_forensics.analyze'])

# Setup Database
with app.app_context():
    setup_database()


# Dashboard Route
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/email-forensic')
@login_required
def email_forensic():
    return render_template('email_forensic.html')

def validate_file_signature(file_storage, expected_signature):
    file_storage.seek(0)
    header = file_storage.read(len(expected_signature))
    file_storage.seek(0)
    return header == expected_signature

@app.route('/usb-forensic', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour", methods=['POST'])
def usb_forensic():
    results = None
    hive_name = None
    
    if request.method == 'POST':
        if 'system_hive' not in request.files:
            flash('No SYSTEM hive part', 'error')
            return redirect(request.url)
            
        hive_file = request.files['system_hive']
        if hive_file.filename == '':
            flash('No selected hive file', 'error')
            return redirect(request.url)
            
        # Magic bytes validation for SYSTEM hive (b'regf')
        if not validate_file_signature(hive_file, b'regf'):
            flash("This doesn't appear to be a valid registry hive file.", "error")
            return redirect(request.url)

        # Secure filename and generate isolated path
        hive_filename = secure_filename(hive_file.filename)
        if not hive_filename:
            hive_filename = "system.hive"
        unique_hive_id = f"{uuid.uuid4().hex[:8]}_{hive_filename}"
        hive_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_hive_id)
        
        evtx_paths = []
        upload_id = request.form.get('upload_id')
        
        try:
            hive_file.save(hive_path)

            # Handle optional EVTX logs
            for log_field in ['config_log', 'management_log']:
                if log_field in request.files and request.files[log_field].filename != '':
                    evtx_file = request.files[log_field]
                    
                    # Magic bytes validation for EVTX logs (b'ElfFile\x00')
                    if not validate_file_signature(evtx_file, b'ElfFile\x00'):
                        flash("This doesn't appear to be a valid EVTX event log file.", "error")
                        return redirect(request.url)
                        
                    evtx_filename = secure_filename(evtx_file.filename)
                    if not evtx_filename:
                        evtx_filename = "event.evtx"
                    evtx_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex[:8]}_{evtx_filename}")
                    evtx_file.save(evtx_path)
                    evtx_paths.append(evtx_path)
                    
                    logger.debug(f"[DEBUG] Received {log_field}: {evtx_file.filename} -> saved as {evtx_filename}")
                    logger.debug(f"[DEBUG] File size: {os.path.getsize(evtx_path)} bytes")

            # 1. Parse Hive (usbstor & mountdev2)
            raw_output = run_regripper(hive_path, 'usbstor')
            devices = parse_usbstor_output(raw_output)
            
            raw_mountdev = ""
            try:
                raw_mountdev = run_regripper(hive_path, 'mountdev2')
            except Exception:
                pass

            from tools.registry_evidence_service import RegistryEvidenceService
            mounted_artifacts = RegistryEvidenceService().parse_mounted_devices(raw_mountdev)

            # 3. Event Correlation
            events = []
            if evtx_paths:
                parsed_events = []
                for ep in evtx_paths:
                    logger.debug(f"[DEBUG] Passing EVTX to parse_usb_events: {ep}")
                    parsed_events.extend(parse_usb_events(ep, upload_id=upload_id))
                logger.debug(f"[DEBUG] parse_usb_events returned {len(parsed_events)} events total")
                events = correlate_events_with_devices(parsed_events, devices)
                logger.debug(f"[DEBUG] correlate_events_with_devices returned {len(events)} correlated events")
                
            # Save to Database using unique_hive_id for distinguishable sessions
            insert_usb_devices(devices, source_hive=unique_hive_id)
            
            # 2. Risk Analysis (now using events)
            risks = analyze_risk(devices, events)

            # 4. USB Session Analytics & Event Correlation Engine
            correlator = UsbSessionCorrelator()
            sessions = correlator.correlate(devices, events)
            from tools.event_correlation_service import EventCorrelationService
            sessions = EventCorrelationService().process_and_enrich_sessions(sessions, mounted_artifacts)
            analytics = UsbAnalyticsService.calculate_analytics(sessions, devices)
            from tools.summary_service import InvestigationSummaryService
            summary = InvestigationSummaryService.generate_summary(analytics, sessions, devices)
                
            # matches are removed
            matches = []
            
            # Add timedelta for IST conversion directly on the objects for HTML rendering
            for d in devices:
                if d.last_write_time:
                    d.last_write_time = d.last_write_time + timedelta(hours=5, minutes=30)

            serialized_sessions = [s.to_dict() for s in sessions]

            results = {
                'devices': devices,
                'risks': risks,
                'events': events,
                'matches': matches,
                'sessions': sessions,
                'analytics': analytics,
                'summary': summary
            }
            
            # Save results in session so they can be picked up by the PDF generator & export APIs
            serialized_devices = []
            for d in devices:
                lw_time_str = None
                if d.last_write_time:
                    lw_time_str = d.last_write_time.isoformat()
                
                serialized_devices.append({
                    'vendor': d.vendor, 'product': d.product, 'revision': d.revision, 
                    'serial_number': d.serial_number, 'friendly_name': d.friendly_name, 
                    'last_write_time': lw_time_str
                })
                
            serialized_results = {
                'devices': serialized_devices,
                'risks': risks,
                'events': events,
                'matches': matches,
                'sessions': serialized_sessions,
                'analytics': analytics,
                'summary': summary
            }

            results_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_hive_id}_results.json")
            with open(results_file, 'w') as f:
                json.dump(serialized_results, f)
                
            hive_name = unique_hive_id
            
        except TimeoutError as e:
            flash(str(e), 'error')
        except Exception as e:
            flash(f'Error analyzing files: {str(e)}', 'error')
            
        finally:
            # Clean up uploaded files and temp progress log
            if 'hive_path' in locals() and os.path.exists(hive_path):
                try:
                    os.remove(hive_path)
                except Exception:
                    pass
            for ep in evtx_paths:
                if os.path.exists(ep):
                    try:
                        os.remove(ep)
                    except Exception:
                        pass
            if upload_id:
                prog_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{secure_filename(upload_id)}_progress.json')
                if os.path.exists(prog_file):
                    try:
                        os.remove(prog_file)
                    except Exception:
                        pass
                
    return render_template('usb_forensic.html', results=results, hive_name=hive_name)

@app.route('/progress/<upload_id>')
@login_required
def get_progress(upload_id):
    prog_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{secure_filename(upload_id)}_progress.json')
    if os.path.exists(prog_file):
        try:
            with open(prog_file, 'r') as f:
                data = json.load(f)
                return data
        except Exception:
            pass
    return {'status': 'Analyzing...'}

@app.route('/usb-forensic/export-json/<hive_name>')
@login_required
def export_usb_sessions_json(hive_name):
    results_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{secure_filename(hive_name)}_results.json")
    if not os.path.exists(results_file):
        flash('Session data expired or not found. Please re-run analysis.', 'error')
        return redirect(url_for('usb_forensic'))
        
    with open(results_file, 'r') as f:
        data = json.load(f)

    json_str = json.dumps(data.get('sessions', []), indent=2)
    from flask import Response
    return Response(
        json_str,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=USB_Sessions_{hive_name[:8]}.json'}
    )

@app.route('/usb-forensic/export-csv/<hive_name>')
@login_required
def export_usb_sessions_csv(hive_name):
    import csv
    import io
    from flask import Response
    
    results_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{secure_filename(hive_name)}_results.json")
    if not os.path.exists(results_file):
        flash('Session data expired or not found. Please re-run analysis.', 'error')
        return redirect(url_for('usb_forensic'))
        
    with open(results_file, 'r') as f:
        data = json.load(f)

    sessions = data.get('sessions', [])
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write CSV Header
    writer.writerow([
        'Session ID', 'Device Name', 'Vendor', 'Product', 'Serial Number',
        'VID', 'PID', 'Connected Timestamp', 'Disconnected Timestamp',
        'Duration', 'Status', 'Registry Source', 'Event Log Source', 'Session Hash'
    ])
    
    for s in sessions:
        writer.writerow([
            s.get('session_id', ''),
            s.get('device_name', ''),
            s.get('vendor', ''),
            s.get('product', ''),
            s.get('serial_number', ''),
            s.get('vid', ''),
            s.get('pid', ''),
            s.get('connected_timestamp', ''),
            s.get('disconnected_timestamp', ''),
            s.get('duration_formatted', ''),
            s.get('status', ''),
            s.get('registry_source', ''),
            s.get('event_log_source', ''),
            s.get('session_hash', '')
        ])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=USB_Sessions_{hive_name[:8]}.csv'}
    )

@app.route('/usb-forensic/report/<hive_name>')
@login_required
def generate_usb_report(hive_name):
    from datetime import datetime
    from usbstor_parser import UsbDevice
    
    results_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{secure_filename(hive_name)}_results.json")
    if not os.path.exists(results_file):
        flash('Report data expired or not found. Please run analysis again.', 'error')
        return redirect(url_for('usb_forensic'))
        
    with open(results_file, 'r') as f:
        data = json.load(f)
        
    # Reconstruct objects
    devices = []
    for d in data['devices']:
        dt = datetime.fromisoformat(d['last_write_time']) if d['last_write_time'] else None
        devices.append(UsbDevice(vendor=d['vendor'], product=d['product'], revision=d['revision'],
                                 serial_number=d['serial_number'], friendly_name=d['friendly_name'],
                                 parent_id_prefix=None, last_write_time=dt))
                                 
    sessions = [UsbSession.from_dict(s) for s in data.get('sessions', [])]
                                 
    results = {
        'devices': devices,
        'risks': data['risks'],
        'events': data['events'],
        'matches': data['matches'],
        'sessions': sessions,
        'analytics': data.get('analytics', {})
    }
    
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{secure_filename(hive_name)}.pdf")
    generate_pdf_report(results, pdf_path, case_name="USB Forensic Analysis")
    
    return send_file(pdf_path, as_attachment=True, download_name="USB_Forensic_Report.pdf")

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=debug_mode, port=port)
