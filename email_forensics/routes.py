"""
email_forensics/routes.py

Flask Blueprint routes for Module 2 (Email Forensic Analysis) of Forenix.
Provides /module2 GET (upload page), /module2/analyze POST (analysis pipeline & DB persistence),
/module2/results/<id> GET (results view with ownership check), and /module2/results/<id>/pdf GET (PDF report export).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import uuid
import json
import logging
from pathlib import Path

from .parser import parse_email_file, InvalidEmailFileError
from .auth_checks import run_auth_checks
from .domain_intel import run_domain_intel
from .url_analysis import run_url_analysis
from .attachment_analysis import run_attachment_analysis
from .header_integrity import run_header_integrity_check
from .html_analysis import run_html_analysis
from .content_analysis import run_content_analysis
from .domain_age import run_domain_age_check
from .reputation_checks import run_reputation_checks
from .risk_scoring import calculate_risk_score

from database import insert_email_analysis, get_email_analysis_by_id, get_email_analyses_by_user
from tools.report_generator import generate_email_pdf_report


logger = logging.getLogger(__name__)

email_bp = Blueprint('email_forensics', __name__)

ALLOWED_EXTENSIONS = {'.eml', '.msg'}


def is_allowed_email_file(filename: str) -> bool:
    """Checks if filename has .eml or .msg extension."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


@email_bp.route('/module2', methods=['GET'])
@email_bp.route('/email-forensic', methods=['GET'])
@login_required
def upload():
    """Renders the Email Forensic upload page with recent user analysis history."""
    past_analyses = get_email_analyses_by_user(current_user.id)
    return render_template('module2_upload.html', past_analyses=past_analyses)


@email_bp.route('/module2/analyze', methods=['POST'])
@login_required
def analyze():
    """
    POST route accepting uploaded .eml / .msg files.
    Runs all 6 analysis functions in sequence (parser -> auth_checks -> domain_intel -> url_analysis -> attachment_analysis -> risk_scoring),
    persists the full result JSON into SQLite email_analyses table, deletes temporary upload from disk, and redirects to results page.
    """
    if 'email_file' not in request.files:
        flash("No file part provided in upload request.", "error")
        return redirect(url_for('email_forensics.upload'))

    file = request.files['email_file']
    if not file or file.filename == '':
        flash("Please select an .eml or .msg email file to analyze.", "error")
        return redirect(url_for('email_forensics.upload'))

    filename = secure_filename(file.filename)
    if not filename:
        filename = "uploaded_email.eml"

    if not is_allowed_email_file(filename):
        flash("Invalid file extension. Only .eml and .msg files are supported.", "error")
        return redirect(url_for('email_forensics.upload'))

    # Save to isolated temporary upload folder outside static web root
    upload_dir = current_app.config.get('UPLOAD_FOLDER', os.path.join(current_app.root_path, 'uploads', 'tmp'))
    os.makedirs(upload_dir, exist_ok=True)
    
    unique_file_id = f"{uuid.uuid4().hex[:8]}_{filename}"
    temp_path = os.path.join(upload_dir, unique_file_id)

    try:
        raw_bytes = file.read()
        file.seek(0)
        file.save(temp_path)

        # 1. File Parsing Foundation
        parsed_email = parse_email_file(temp_path)

        # 2. Authentication Checks (SPF, DKIM, DMARC)
        auth_result = run_auth_checks(parsed_email, raw_bytes=raw_bytes, file_path=temp_path)

        # 3. Domain Intelligence Layer (tldextract, homograph, typosquatting)
        domain_result = run_domain_intel(parsed_email)

        # 4. URL & Link Analysis Layer
        url_result = run_url_analysis(parsed_email)

        # 5. Attachment Risk Analysis Layer
        attachment_result = run_attachment_analysis(parsed_email)

        # 6. Header Integrity Layer
        header_result = run_header_integrity_check(parsed_email)

        # 7. HTML Content Analysis Layer
        html_result = run_html_analysis(parsed_email)

        # 8. Content / Scam Keyword Analysis Layer
        content_result = run_content_analysis(parsed_email)

        # 9. Domain Age Check Layer
        domain_age_result = run_domain_age_check(parsed_email)

        # 10. Live Reputation Intelligence Layer (VirusTotal & AbuseIPDB)
        reputation_result = run_reputation_checks(parsed_email, url_result=url_result, auth_result=auth_result)

        # 11. Risk Scoring Engine
        risk_result = calculate_risk_score(
            parsed_email, auth_result, domain_result, url_result,
            attachment_result, header_result, html_result, content_result,
            domain_age_result, reputation_result
        )

        # Bundle full complete breakdown for database persistence
        full_payload = {
            'metadata': {
                'filename': filename,
                'file_size': len(raw_bytes),
                'unique_id': unique_file_id,
            },
            'parsed_email': parsed_email.to_dict(),
            'auth_result': auth_result.to_dict(),
            'domain_result': domain_result.to_dict(),
            'url_result': url_result.to_dict(),
            'attachment_result': attachment_result.to_dict(),
            'header_result': header_result.to_dict(),
            'html_result': html_result.to_dict(),
            'content_result': content_result.to_dict(),
            'domain_age_result': domain_age_result.to_dict(),
            'reputation_result': reputation_result.to_dict(),
            'risk_result': risk_result.to_dict(),
        }



        full_json_str = json.dumps(full_payload, indent=2, default=str)

        # Store in database
        analysis_id = insert_email_analysis(
            user_id=current_user.id,
            filename=filename,
            risk_score=risk_result.total_score,
            risk_band=risk_result.risk_band,
            hard_flagged=risk_result.hard_flagged,
            full_result_json=full_json_str
        )

        flash("Email analysis completed successfully.", "success")
        return redirect(url_for('email_forensics.results', analysis_id=analysis_id))

    except InvalidEmailFileError as e:
        flash(f"Invalid email file: {str(e)}", "error")
        return redirect(url_for('email_forensics.upload'))
    except Exception as e:
        logger.error(f"Error during email forensic analysis: {e}", exc_info=True)
        flash(f"An unexpected error occurred during email analysis: {str(e)}", "error")
        return redirect(url_for('email_forensics.upload'))
    finally:
        # PART B Cleanup: Immediately delete temporary raw upload file from disk after analysis finishes
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@email_bp.route('/module2/results/<int:analysis_id>', methods=['GET'])
@login_required
def results(analysis_id: int):
    """Retrieves and renders a specific past email forensic analysis result with strict user ownership check."""
    record = get_email_analysis_by_id(analysis_id)
    if not record:
        flash("Analysis record not found.", "error")
        return redirect(url_for('email_forensics.upload'))

    # PART C Security Hardening: Ownership Check
    if int(record['user_id']) != int(current_user.id):
        flash("Access denied: You can only view your own forensic analysis reports.", "error")
        return redirect(url_for('email_forensics.upload'))

    try:
        data = json.loads(record['full_result_json'])
    except Exception as e:
        flash("Corrupt analysis data payload.", "error")
        return redirect(url_for('email_forensics.upload'))

    return render_template('module2_results.html', record=record, data=data)


@email_bp.route('/module2/results/<int:analysis_id>/pdf', methods=['GET'])
@login_required
def generate_pdf(analysis_id: int):
    """Generates and downloads a ReportLab PDF report for an email analysis with ownership enforcement."""
    record = get_email_analysis_by_id(analysis_id)
    if not record:
        flash("Analysis record not found.", "error")
        return redirect(url_for('email_forensics.upload'))

    # PART A & C Security Hardening: Ownership Check
    if int(record['user_id']) != int(current_user.id):
        flash("Access denied: You can only export PDF reports for your own analyses.", "error")
        return redirect(url_for('email_forensics.upload'))



    try:
        data = json.loads(record['full_result_json'])
    except Exception as e:
        flash("Corrupt analysis data payload.", "error")
        return redirect(url_for('email_forensics.upload'))

    upload_dir = current_app.config.get('UPLOAD_FOLDER', os.path.join(current_app.root_path, 'uploads', 'tmp'))
    os.makedirs(upload_dir, exist_ok=True)

    pdf_filename = f"Email_Forensic_Report_{analysis_id}.pdf"
    unique_pdf_path = os.path.join(upload_dir, f"{uuid.uuid4().hex[:8]}_{pdf_filename}")

    try:
        generate_email_pdf_report(data, unique_pdf_path, case_name="Email Forensic Analysis")
        return send_file(unique_pdf_path, as_attachment=True, download_name=pdf_filename)
    except Exception as e:
        logger.error(f"Error generating Email Forensic PDF report: {e}", exc_info=True)
        flash(f"Failed to generate PDF report: {str(e)}", "error")
        return redirect(url_for('email_forensics.results', analysis_id=analysis_id))
    finally:
        # Cleanup temporary PDF file after download response finishes (handled via send_file)
        pass
