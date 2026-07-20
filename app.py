import os
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
import json

from database import setup_database, get_user_by_id, insert_usb_devices, get_all_devices
from auth import auth_bp, User
from regripper_runner import run_regripper
from usbstor_parser import parse_usbstor_output
from tools.event_parser import parse_usb_events, correlate_events_with_devices, analyze_risk
from tools.report_generator import generate_pdf_report

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

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
        return User(user_row['id'], user_row['username'], user_row['email'], user_row['is_verified'])
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

# Register Blueprint
app.register_blueprint(auth_bp)

# Setup Database
with app.app_context():
    setup_database()

UPLOAD_FOLDER = 'temp_samples'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

@app.route('/usb-forensic', methods=['GET', 'POST'])
@login_required
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
            
        # Secure filename and save
        hive_filename = secure_filename(hive_file.filename)
        # Use UUID to prevent collisions if multiple users upload same name
        unique_hive_id = f"{uuid.uuid4().hex[:8]}_{hive_filename}"
        hive_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_hive_id)
        hive_file.save(hive_path)
        
        # Handle optional EVTX
        evtx_path = None
        if 'event_log' in request.files and request.files['event_log'].filename != '':
            evtx_file = request.files['event_log']
            evtx_filename = secure_filename(evtx_file.filename)
            evtx_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex[:8]}_{evtx_filename}")
            evtx_file.save(evtx_path)
            
        try:
            # 1. Parse Hive
            raw_output = run_regripper(hive_path, 'usbstor')
            devices = parse_usbstor_output(raw_output)
            
            # Save to Database
            insert_usb_devices(devices, source_hive=hive_filename)
            
            # 2. Risk Analysis
            risks = analyze_risk(devices)
            
            # 3. Event Correlation
            events = []
            if evtx_path:
                parsed_events = parse_usb_events(evtx_path)
                events = correlate_events_with_devices(parsed_events, devices)
                
            # 4. Multi-Machine Matching
            all_db_devices = get_all_devices()
            matches = []
            current_serials = [d.serial_number for d in devices if d.serial_number]
            for db_dev in all_db_devices:
                if db_dev['source_hive'] != hive_filename and db_dev['serial_number'] in current_serials:
                    matches.append({
                        'device_name': db_dev['friendly_name'] or f"{db_dev['vendor']} {db_dev['product']}",
                        'serial_number': db_dev['serial_number'],
                        'other_hive': db_dev['source_hive']
                    })
            
            results = {
                'devices': devices,
                'risks': risks,
                'events': events,
                'matches': matches
            }
            
            # Save results in session so they can be picked up by the PDF generator
            # Need to serialize devices manually as they are dataclass objects
            serialized_results = {
                'devices': [{'vendor': d.vendor, 'product': d.product, 'revision': d.revision, 
                             'serial_number': d.serial_number, 'friendly_name': d.friendly_name, 
                             'last_write_time': d.last_write_time.isoformat() if d.last_write_time else None} for d in devices],
                'risks': risks,
                'events': events,
                'matches': matches
            }
            # We can use file-based caching for large results if session cookie is too small, 
            # but for this demo, we write a temp JSON file.
            results_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_hive_id}_results.json")
            with open(results_file, 'w') as f:
                json.dump(serialized_results, f)
                
            hive_name = unique_hive_id
            
        except Exception as e:
            flash(f'Error analyzing files: {str(e)}', 'error')
            
        finally:
            # Clean up uploaded files
            if os.path.exists(hive_path):
                os.remove(hive_path)
            if evtx_path and os.path.exists(evtx_path):
                os.remove(evtx_path)
                
    return render_template('usb_forensic.html', results=results, hive_name=hive_name)

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
                                 
    results = {
        'devices': devices,
        'risks': data['risks'],
        'events': data['events'],
        'matches': data['matches']
    }
    
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{secure_filename(hive_name)}.pdf")
    generate_pdf_report(results, pdf_path, case_name="USB Forensic Analysis")
    
    return send_file(pdf_path, as_attachment=True, download_name="USB_Forensic_Report.pdf")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
