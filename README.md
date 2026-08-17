# Forenix — Digital Forensics Investigation Platform

## Overview

**Forenix** is a modular digital forensics platform engineered to assist forensic investigators, incident responders, and security analysts in processing, correlating, and evaluating digital evidence across desktop and system environments.

Built with an architecture centered around independent, domain-specific forensic modules, Forenix establishes a unified evidence analysis environment powered by a core set of non-negotiable engineering and design principles:
- **Zero Fabricated Data**: Forenix never outputs synthetic confidence metrics, mock risk scores, or speculative AI assertions. All displayed metrics originate directly from raw, verifiable forensic artifacts.
- **Honest Disclosure of Limitations**: Forensic boundary limits—such as Windows Registry `Last Write Time` mechanics—are surfaced transparently directly in the user interface rather than obfuscated.
- **Rule-Based Explainable Logic**: Deterministic, auditable rule sets are prioritized over black-box machine learning models wherever legal defensibility and evidence auditability matter.
- **Consistent Platform Security**: Enterprise-grade security standards (RBAC, CSRF defense, rate limiting, magic-byte validation, security headers) apply uniformly across every module.

---

## Module 1: USB Device Forensic Analysis (Status: Complete)

### Problem Addressed
USB storage devices represent one of the primary vectors for physical data exfiltration, malware insertion, and unauthorized device connection in corporate and enterprise environments. Because standard USB connections do not leave network traffic traces, investigators must extract, parse, and correlate system registry keys and Windows Event Logs to establish timeline fidelity.

### Forensic Engine & Implementation Details
- **Registry Extraction**: Automates the extraction of USB artifact records from Windows `SYSTEM` registry hives using **RegRipper** invoked via controlled Python `subprocess` execution.
- **Regex & Data Parsing**: Parses raw RegRipper output using regex structures to extract vendor names, product IDs, serial numbers, friendly names, and registry `Last Write Time` timestamps.
- **Windows Event Log Correlation**: Leverages `python-evtx` to parse native Windows Event Logs (`.evtx`) across both **Device Configuration** (`Microsoft-Windows-Kernel-PnP/Configuration`, Event ID 20001/20003) and **Device Management** (`Microsoft-Windows-UserPnp/DeviceInstall`, Event ID 20001) channels.
- **Session Reconstruction & Cryptographic Integrity**: Correlates connect/disconnect event pairs into discrete device sessions. Every reconstructed session generates a unique **SHA-256 integrity hash** generated from device serial number, connect timestamp, and disconnect timestamp for evidence auditability.
- **Rule-Based Risk Analysis**: Evaluates USB connection timelines for operational anomalies, including connection during unusual hours (e.g. late-night activity between 11 PM and 5 AM) and rapid reconnection patterns.
- **Forensic PDF Reporting**: Generates client-ready, multi-page forensic reports utilizing **ReportLab**, featuring executive summaries, device inventories, session breakdowns, and anomaly flags.
- **Database Persistence**: Stores analysis sessions in **SQLite** with built-in hash deduplication to eliminate redundant parsing of historical evidence.

---

## Module 2: Email Forensic Analysis (Status: Planned)

### Problem Addressed
Email spoofing, BEC (Business Email Compromise), and sophisticated phishing attacks exploit weaknesses in email header verification, visual domain confusion, and malicious attachments. Forensic analysts require a structured environment to parse, validate, and score raw email files (`.eml` / `.msg`).

### Planned Features & Architecture
*Note: Module 2 is currently in the planning and architecture phase.*
- **Multi-Format Parsing**: Planned integration of Python's native `email` module for RFC 822 (`.eml`) parsing and `extract-msg` for Microsoft Outlook (`.msg`) file extraction into a normalized internal data structure (`ParsedEmail`).
- **Cryptographic Authentication Verification**: Planned execution of live DNS lookups to validate **SPF** (via `pyspf`), **DKIM** (via `dkimpy`), and **DMARC** (via `checkdmarc` / `dnspython`).
- **Spoofing & Impersonation Logic**: Planned detection of envelope sender vs. `From` address mismatches, return-path mismatches, and display name spoofing.
- **URL & Domain Mismatch Analysis**: Extraction and parsing of HTML/plaintext links using `tldextract` to catch domain mismatches (e.g., link text claiming `paypal.com` but pointing to an attacker domain), typosquatting (via `rapidfuzz`), homograph/punycode tricks (via `idna`), and raw IP destinations.

---

## Module 3: Deepfake Detection (Status: Planned)

### Problem Addressed
The rapid escalation of generative synthetic media creates severe risks of video tampering, identity impersonation, and digital evidence fabrication.

### Planned Features & Architecture
*Note: Module 3 is currently in the planning and architecture phase.*
- **Frame Extraction**: Planned frame-by-frame decomposition of uploaded video files using **OpenCV**.
- **Face & Region Detection**: Planned facial alignment and landmark tracking across frame sequences utilizing **MediaPipe**.
- **Pretrained Neural Network Inference**: Planned classification using established, battle-tested pretrained models via **PyTorch** or **TensorFlow** (e.g. EfficientNet / MesoNet backbones fine-tuned on deepfake benchmarks).
- **Design Constraint Decision**: *Training a deepfake classifier from scratch was explicitly ruled out due to massive compute requirements, dataset curation overhead, and poor generalization performance compared to verified pretrained weights.*

---

## Authentication & Security (Platform-wide)

Security is built directly into the foundation of Forenix and applies across all modules:
- **Password Hashing**: Secure password hashing implemented via Werkzeug (`scrypt` / `pbkdf2:sha256`).
- **OAuth 2.0 Integration**: Third-party authentication via Google OAuth 2.0 powered by `Authlib`.
- **OTP Password Reset**: Two-factor password reset workflow utilizing 6-digit OTP codes delivered via SendGrid.
- **Session Management**: Session timeout enforcement, secure HTTP-only and SameSite cookie flags, and account lockout protection after repeated failed login attempts.
- **Rate Limiting**: Endpoint abuse protection enforced via `Flask-Limiter` (e.g. IP/user rate caps on authentication routes).
- **Security Headers**: Strict response header hardening including `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, and Content Security Policy directives.
- **File Upload Validation**: Magic-byte signature checking for all uploaded evidence files to prevent extension-spoofing attacks, paired with automatic temporary file cleanup.

---

## Tech Stack

### Current Stack (Core Platform & Module 1)
- **Language**: Python 3.10+
- **Web Framework**: Flask
- **Registry Extraction**: RegRipper (via `subprocess`)
- **Event Log Parsing**: `python-evtx`
- **Database**: SQLite3
- **PDF Generation**: ReportLab
- **Frontend Styling**: Vanilla CSS & Tailwind CSS CDN
- **Authentication & Security**: Authlib (Google OAuth), SendGrid API, Werkzeug Security, Flask-WTF (CSRF Protection), Flask-Limiter

### Planned Additions (Modules 2 & 3)
- **Email Parsing & Auth**: `extract-msg`, `pyspf`, `dkimpy`, `checkdmarc`, `dnspython`, `tldextract`, `rapidfuzz`
- **Media & Deepfake Analysis**: OpenCV (`opencv-python`), MediaPipe, PyTorch / TensorFlow

---

## Project Structure

```text
Forenix/
├── app.py                      # Primary Flask application server & route definitions
├── auth.py                     # Authentication blueprint (Login, Signup, OAuth, OTP, Logout)
├── database.py                 # SQLite database initialization, schemas, and helper queries
├── email_service.py            # SendGrid email integration for OTP delivery
├── regripper_runner.py         # Subprocess runner for executing RegRipper plugins
├── usbstor_parser.py           # USBSTOR registry output parsing and regex extraction
├── settings.py                 # User settings, profile updates, and security preferences
├── schema.sql                  # Relational database schema definition
├── requirements.txt            # Python dependencies
├── .env.example                # Template environment configuration file
├── adapters/                   # Event log correlation adapters
│   └── event_log_adapter.py    # EVTX parsing and timeline correlation engine
├── tools/                      # Report generation utilities
│   └── report_generator.py     # ReportLab PDF building logic
├── templates/                  # Jinja2 HTML templates
│   ├── app_base.html           # Main authenticated app layout (sidebar, navbar)
│   ├── base.html               # Unauthenticated layout (auth pages)
│   ├── dashboard.html          # Module hub dashboard
│   ├── usb_forensic.html       # Module 1 USB Forensic interface
│   ├── settings.html           # User settings view
│   └── auth/                   # Authentication view templates
├── static/                     # Static assets (CSS, JS, images)
├── temp_samples/               # Forensic sample evidence files for testing
└── uploads/                    # Temporary secure storage for uploaded hives/logs
```

---

## Setup Instructions

### 1. Prerequisites & Environment Setup
Clone the repository and create a Python virtual environment:

```bash
git clone https://github.com/sarthakpolshettiwar-alt/Nextrace.git
cd Nextrace
python -m venv venv
```

Activate the virtual environment:
- **Windows (PowerShell)**: `.\venv\Scripts\Activate.ps1`
- **Linux/macOS**: `source venv/bin/activate`

### 2. Install Dependencies
Install all required Python packages:

```bash
pip install -r requirements.txt
```

### 3. RegRipper Setup Note
Ensure RegRipper (`rip.exe` or `rip.pl`) is installed on your system path or placed within the project root directory so `regripper_runner.py` can invoke RegRipper plugins (`usbstor`, `devclass`) during registry analysis.

### 4. Configure Environment Variables
Copy the `.env.example` file to `.env` and fill in the required keys:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
SECRET_KEY=your_random_secret_key_here
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
SENDGRID_API_KEY=your_sendgrid_api_key
SENDER_EMAIL=noreply@yourdomain.com
```

### 5. Initialize Database & Run Application
Run the Flask server:

```bash
python app.py
```

Open your browser and navigate to `http://localhost:5000`.

---

## Getting a SYSTEM Hive File for Testing

To test Module 1 on a live Windows host, extract the active `SYSTEM` registry hive using an elevated PowerShell prompt:

```powershell
# Open PowerShell as Administrator
reg save HKLM\SYSTEM system_test.hive /y
```

Upload the resulting `system_test.hive` file on the **USB Forensic Analysis** page (`/usb-forensic`) to analyze USB connection history.

---

## Design Principles

1. **No Fabricated or Placeholder Data**: Forenix explicitly rejects fake confidence scores, synthetic risk percentages, or arbitrary AI output. During early development, a proposed "confidence score" feature was evaluated and deliberately removed because it introduced non-deterministic, unprovable data. Every figure in Forenix is tied directly to raw forensic artifacts.
2. **Honest UI Disclosure of Limitations**: Windows Registry `Last Write Time` records update when ANY USB device under a key is modified. Forenix directly discloses this limitation in the UI banner and reports, prompting analysts to upload Event Logs for microsecond-accurate connect/disconnect timeline correlation.
3. **Deterministic & Explainable Logic Over Black-Box ML**: In digital forensics, evidence must stand up in court. Deterministic rules, regex parsers, and direct artifact extractions are used wherever auditability is mandatory.

---

## Roadmap

- [x] **Module 1: USB Device Forensic Analysis** (Registry parsing, EVTX event log correlation, SHA-256 session integrity, ReportLab PDF export).
- [ ] **Module 2: Email Forensic Analysis** (Header parsing, SPF/DKIM/DMARC validation, spoofing detection, domain & link risk scoring).
- [ ] **Module 3: Deepfake Detection** (OpenCV frame extraction, MediaPipe face tracking, pretrained neural network inference).

---

## License

*Placeholder — License to be added.*

---

## Disclaimer

Forenix is designed strictly for educational, research, authorized incident response, and legal digital forensics investigations. Unauthorized analysis of computer systems, registry hives, or email records without explicit authorization is strictly prohibited.