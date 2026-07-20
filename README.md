# NexTrace — Digital Forensics Investigation Platform

NexTrace is a modular digital forensics platform built to help investigators analyze digital evidence from Windows systems in a structured, auditable way. The platform is designed around independent forensic modules, with **USB Device Forensic Analysis** as the first fully functional module.

## What It Does

USB devices are one of the most common vectors for data theft and unauthorized data transfer, since they leave no network trace. NexTrace's USB Forensic module automates the process of extracting, correlating, and reporting on USB connection history from a Windows machine, turning a manual, multi-hour registry investigation into a guided, few-click workflow.

## Features

### USB Forensic Analysis
- **Registry Hive Upload** — accepts a Windows `SYSTEM` registry hive file for analysis
- **USB Device Detection** — extracts device name, vendor, product, serial number, and connection timestamps using RegRipper
- **Connection Timeline** — chronological view of when each device was connected
- **Windows Event Log Correlation** — optionally upload a `.evtx` event log; matches Event IDs (2003, 2100 series) to registry-detected devices to confirm actual usage timestamps
- **Risk & Anomaly Flagging** — rule-based detection of unusual activity (e.g. connections outside standard business hours)
- **Multi-Machine Device Matching** — cross-references device serial numbers across multiple analyzed hives to detect the same USB device appearing on different machines
- **PDF Report Generation** — compiles all findings into a downloadable forensic report

### Authentication & Security
- Email/password login with hashed passwords (never stored in plain text)
- Google OAuth sign-in
- OTP-based password reset via email (SendGrid)
- Account lockout after repeated failed login attempts
- Session timeout after inactivity
- CSRF protection on all forms
- "Trust this device" option for reduced login friction
- Full login activity log for auditability

### Coming Soon
- Email Forensic Analysis (header parsing, SPF/DKIM/DMARC spoofing detection)
- Deepfake Detection (video/image manipulation analysis)

## Tech Stack

- **Backend:** Python, Flask
- **Registry Analysis:** RegRipper (third-party forensic tool)
- **Event Log Parsing:** python-evtx
- **Database:** SQLite
- **Authentication:** Flask sessions, Authlib (Google OAuth), Flask-WTF (CSRF)
- **Email Delivery:** SendGrid API
- **Report Generation:** ReportLab
- **Frontend:** HTML, CSS, JavaScript, Tailwind CSS

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/sarthakpolshettiwar-alt/Nextrace.git
cd Nextrace
```

### 2. Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up RegRipper
RegRipper is a third-party tool and is not bundled in this repository. Download it separately and place it at:
```
tools/regripper/
```
Ensure `rip.exe` and the `plugins/` folder are present in that directory.

### 5. Configure environment variables
Copy the example environment file and fill in your own credentials:
```bash
copy .env.example .env      # Windows
cp .env.example .env        # macOS/Linux
```

Required variables in `.env`:
```
SENDGRID_API_KEY=
SENDER_EMAIL=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
SECRET_KEY=
```

### 6. Run the application
```bash
python app.py
```
The app will be available at `http://127.0.0.1:5000`

## Getting a SYSTEM Hive File for Testing

To test the USB Forensic module, you'll need a Windows `SYSTEM` registry hive:

1. Open PowerShell as Administrator
2. Run:
   ```
   reg save HKLM\SYSTEM C:\Users\%USERNAME%\system_test.hive
   ```
3. Upload the resulting file through the USB Forensic module's upload interface

*Note: This only reads a copy of the registry and does not modify your system.*

## Project Structure

```
Nextrace/
├── app.py                  # Main Flask application
├── auth.py                 # Authentication blueprint (login, signup, OAuth, OTP)
├── create_admin.py         # Script to create an initial admin user
├── database.py             # Database connection and queries
├── schema.sql              # SQLite schema
├── regripper_runner.py     # Subprocess wrapper for RegRipper
├── usbstor_parser.py       # Parses RegRipper's USB output into structured data
├── email_service.py        # SendGrid email integration (OTP delivery)
├── tools/
│   ├── event_parser.py     # Windows Event Log (.evtx) correlation
│   ├── report_generator.py # PDF report generation
│   └── regripper/          # RegRipper binary + plugins (not included, see setup)
├── templates/               # HTML templates
└── requirements.txt
```

## Forensic Integrity Principles

This project follows core digital forensics practices:
- Operates only on **copies** of registry hives, never live system files
- No fabricated or placeholder statistics — all displayed data comes from actual parsed results
- Every login/system action is logged for auditability

## Screenshots

*(Add screenshots of the dashboard, USB module, and reports here)*

## License

*(To be added)*

## Disclaimer

This tool is intended for educational and authorized forensic investigation purposes only. Always ensure you have proper authorization before analyzing any system or device.