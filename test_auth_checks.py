"""
test_auth_checks.py

Test script for email_forensics/auth_checks.py in Forenix (Module 2).
Tests SPF, DKIM, and DMARC validation against legitimate domain emails, phishing samples,
and missing-field edge cases. Prints all fields of AuthResult clearly labeled with raw DNS records.
"""

from pathlib import Path
from email.message import EmailMessage
import sys

from email_forensics.parser import parse_email_file, ParsedEmail
from email_forensics.auth_checks import run_auth_checks, AuthResult


def create_gmail_sample_eml(filepath: Path) -> None:
    """Create a sample EML representing a legitimate email from gmail.com."""
    msg = EmailMessage()
    msg['From'] = 'Sender Name <user@gmail.com>'
    msg['To'] = 'recipient@company.com'
    msg['Subject'] = 'Meeting Agenda for Tomorrow'
    msg['Date'] = 'Wed, 05 Aug 2026 11:30:00 +0000'
    msg['Message-ID'] = '<legit-gmail-12345@mail.gmail.com>'
    
    # Received header from Google MX sender (209.85.220.41 is in Google's published SPF record)
    msg.add_header('Received', 'from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.google.com with SMTPS id g123; Wed, 05 Aug 2026 11:30:05 +0000')

    msg.set_content("Hello, here is the agenda for tomorrow's meeting.")
    
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(msg.as_bytes())


def print_auth_result(label: str, auth_res: AuthResult) -> None:
    """Pretty prints every field of AuthResult clearly labeled for manual verification against dig TXT."""
    print("=" * 85)
    print(f" AUTHENTICATION CHECK RESULTS [{label}]")
    print("=" * 85)
    print(f"  - OVERALL SUMMARY STATUS : {auth_res.summary_status}")
    print()


    # SPF Details
    print("  [1] SPF (Sender Policy Framework):")
    print(f"      - Status           : {auth_res.spf.status}")
    print(f"      - Sender IP Used   : {auth_res.spf.ip_used}")
    print(f"      - Domain Checked   : {auth_res.spf.domain_checked}")
    print(f"      - Raw SPF Record   : {auth_res.spf.raw_record}")
    print(f"      - Details          : {auth_res.spf.details}")
    print()

    # DKIM Details
    print("  [2] DKIM (DomainKeys Identified Mail):")
    print(f"      - Status           : {auth_res.dkim.status}")
    print(f"      - Signing Domain   : {auth_res.dkim.domain_checked}")
    print(f"      - DKIM Selector    : {auth_res.dkim.selector}")
    print(f"      - Fail Reason      : {auth_res.dkim.reason}")
    print()

    # DMARC Details
    print("  [3] DMARC (Domain-based Message Authentication):")
    print(f"      - Status           : {auth_res.dmarc.status}")
    print(f"      - Domain Checked   : {auth_res.dmarc.domain_checked}")
    print(f"      - DMARC Policy (p=): {auth_res.dmarc.policy}")
    print(f"      - Raw DMARC Record : {auth_res.dmarc.raw_record}")
    print(f"      - Details          : {auth_res.dmarc.details}")
    print("=" * 85)
    print()


def main():
    samples_dir = Path("temp_samples")
    gmail_path = samples_dir / "sample_legit_gmail.eml"
    phish_path = samples_dir / "sample_phishing.eml"

    print("\n--- [Step 1] Creating Test Email Samples ---")
    create_gmail_sample_eml(gmail_path)
    print(f"[OK] Created legitimate Gmail sample at: {gmail_path}")

    # 1. Test Legitimate Email (gmail.com)
    print("\n--- [Step 2] Testing Legitimate Email Auth (gmail.com) ---")
    parsed_gmail = parse_email_file(gmail_path)
    auth_gmail = run_auth_checks(parsed_gmail, file_path=gmail_path)
    print_auth_result("LEGITIMATE GMAIL EMAIL", auth_gmail)

    # 2. Test Phishing Sample Email
    print("\n--- [Step 3] Testing Phishing Email Auth ---")
    if phish_path.exists():
        parsed_phish = parse_email_file(phish_path)
        auth_phish = run_auth_checks(parsed_phish, file_path=phish_path)
        print_auth_result("PHISHING EMAIL SAMPLE", auth_phish)
    else:
        print(f"Notice: {phish_path} not found.")

    # 3. Test Missing Field / Incomplete Edge Case
    print("\n--- [Step 4] Testing Missing Fields / Unable to Verify Edge Case ---")
    empty_email = ParsedEmail(
        from_name=None,
        from_address=None,
        to="victim@corp.com",
        subject="No Headers Email",
        date=None,
        return_path=None,
        reply_to=None,
        message_id=None,
        received_headers=[],  # No Received headers
        body_plain="Test",
        body_html=None,
        attachments=[]
    )
    auth_incomplete = run_auth_checks(empty_email)
    print_auth_result("INCOMPLETE EMAIL (MISSING IP & DOMAIN)", auth_incomplete)

    print("[OK] ALL AUTHENTICATION CHECK TESTS COMPLETED.\n")


if __name__ == "__main__":
    main()
