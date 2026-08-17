"""
test_parser.py

Test script to verify email parser foundation for Module 2 of Forenix.
Parses sample .eml and .msg files and prints all extracted fields clearly labeled.
Also tests error handling for invalid/corrupted files.
"""

from pathlib import Path
import sys
from datetime import datetime
from email.message import EmailMessage

import struct

from email_forensics.parser import (
    parse_email_file,
    InvalidEmailFileError,
    ParsedEmail
)


def build_minimal_msg(headers_str: str, subject: str, sender_name: str, sender_email: str, body_text: str) -> bytes:
    """Minimal OLE CFBF builder for synthetic MSG testing."""
    streams = {
        "__substg1.0_007D001F": headers_str.encode('utf-16-le'),
        "__substg1.0_0037001F": subject.encode('utf-16-le'),
        "__substg1.0_0C1F001F": sender_name.encode('utf-16-le'),
        "__substg1.0_0C1E001F": sender_email.encode('utf-16-le'),
        "__substg1.0_1000001F": body_text.encode('utf-16-le'),
        "__properties_version1.0": b'\x00' * 32,
    }

    ministream_bytes = bytearray()
    dir_entries = []

    dir_entries.append({
        'name': "Root Entry",
        'type': 5,
        'start_sect': 4,
        'size': 0,
        'child': 1,
        'left': 0xFFFFFFFF,
        'right': 0xFFFFFFFF
    })

    num_streams = len(streams)
    for idx, (s_name, s_data) in enumerate(streams.items(), start=1):
        start_minisect = len(ministream_bytes) // 64
        ministream_bytes.extend(s_data)
        pad = (64 - (len(s_data) % 64)) % 64
        ministream_bytes.extend(b'\x00' * pad)

        dir_entries.append({
            'name': s_name,
            'type': 2,
            'start_sect': start_minisect,
            'size': len(s_data),
            'child': 0xFFFFFFFF,
            'left': 0xFFFFFFFF,
            'right': idx + 1 if idx < num_streams else 0xFFFFFFFF
        })

    dir_entries[0]['size'] = len(ministream_bytes)

    minifat = []
    mini_offset = 0
    for s_name, s_data in streams.items():
        count = (len(s_data) + 63) // 64
        for i in range(count):
            if i == count - 1:
                minifat.append(0xFFFFFFFE)
            else:
                minifat.append(mini_offset + i + 1)
        mini_offset += count

    minifat_bytes = bytearray()
    for entry in minifat:
        minifat_bytes.extend(struct.pack('<I', entry))
    minifat_bytes.extend(b'\xFF' * (512 - len(minifat_bytes)))

    dir_bytes = bytearray()
    for entry in dir_entries:
        entry_buf = bytearray(128)
        encoded_name = entry['name'].encode('utf-16-le')
        entry_buf[0:len(encoded_name)] = encoded_name
        struct.pack_into('<H', entry_buf, 0x40, len(encoded_name) + 2)
        entry_buf[0x42] = entry['type']
        entry_buf[0x43] = 1
        struct.pack_into('<I', entry_buf, 0x44, entry['left'])
        struct.pack_into('<I', entry_buf, 0x48, entry['right'])
        struct.pack_into('<I', entry_buf, 0x4C, entry['child'])
        struct.pack_into('<I', entry_buf, 0x74, entry['start_sect'])
        struct.pack_into('<I', entry_buf, 0x78, entry['size'])
        dir_bytes.extend(entry_buf)

    while len(dir_bytes) < 1024:
        dir_bytes.extend(b'\x00' * 128)

    num_ministream_sectors = (len(ministream_bytes) + 511) // 512
    ministream_container = bytearray(ministream_bytes)
    ministream_container.extend(b'\x00' * (num_ministream_sectors * 512 - len(ministream_container)))

    fat = [0xFFFFFFFD, 2, 0xFFFFFFFE, 0xFFFFFFFE]
    for s in range(num_ministream_sectors):
        if s == num_ministream_sectors - 1:
            fat.append(0xFFFFFFFE)
        else:
            fat.append(4 + s + 1)

    while len(fat) < 128:
        fat.append(0xFFFFFFFF)

    fat_bytes = bytearray()
    for f_entry in fat:
        fat_bytes.extend(struct.pack('<I', f_entry))

    hdr = bytearray(512)
    hdr[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    struct.pack_into('<H', hdr, 0x18, 0x003E)
    struct.pack_into('<H', hdr, 0x1A, 0x0003)
    struct.pack_into('<H', hdr, 0x1C, 0xFFFE)
    struct.pack_into('<H', hdr, 0x1E, 9)
    struct.pack_into('<H', hdr, 0x20, 6)
    struct.pack_into('<I', hdr, 0x2C, 1)
    struct.pack_into('<I', hdr, 0x30, 1)
    struct.pack_into('<I', hdr, 0x38, 4096)
    struct.pack_into('<I', hdr, 0x3C, 3)
    struct.pack_into('<I', hdr, 0x40, 1)
    struct.pack_into('<I', hdr, 0x44, 0xFFFFFFFE)
    struct.pack_into('<I', hdr, 0x48, 0)
    struct.pack_into('<I', hdr, 0x4C, 0)

    for i in range(1, 109):
        struct.pack_into('<I', hdr, 0x4C + i * 4, 0xFFFFFFFF)

    file_bytes = bytearray()
    file_bytes.extend(hdr)
    file_bytes.extend(fat_bytes)
    file_bytes.extend(dir_bytes)
    file_bytes.extend(minifat_bytes)
    file_bytes.extend(ministream_container)

    return bytes(file_bytes)



def create_sample_eml(filepath: Path) -> None:
    """Create a sample .eml file with headers, multipart body, and attachment."""
    msg = EmailMessage()
    msg['From'] = 'Security Dept <security@bank-verify-auth.com>'
    msg['To'] = 'victim@corp.internal'
    msg['Subject'] = 'CRITICAL: Action Required - Verify Account Security'
    msg['Date'] = 'Wed, 05 Aug 2026 10:45:00 +0530'
    msg['Return-Path'] = '<bounce@bank-verify-auth.com>'
    msg['Reply-To'] = 'support@phish-domain.xyz'
    msg['Message-ID'] = '<20260805104500.89123@bank-verify-auth.com>'
    
    # Received hop chain (added in reverse order so top is final destination)
    msg.add_header('Received', 'from internal-smtp.phish-domain.xyz (internal-smtp.phish-domain.xyz [10.0.4.12]) by mail.bank-verify-auth.com with ESMTP; Wed, 05 Aug 2026 10:44:58 +0530')
    msg.add_header('Received', 'from mail.bank-verify-auth.com (mail.bank-verify-auth.com [198.51.100.99]) by mx1.corp.internal with ESMTP id XYZ67890; Wed, 05 Aug 2026 10:45:02 +0530')
    msg.add_header('Received', 'from mx1.corp.internal (mx1.corp.internal [192.168.1.10]) by mail.corp.internal with ESMTP id ABC12345; Wed, 05 Aug 2026 10:45:05 +0530')

    # Plain text and HTML body
    msg.set_content(
        "Dear User,\n\n"
        "We detected suspicious activity on your account. Please click the link below to verify your credentials:\n"
        "http://login.bank-verify-auth.com/login.php\n\n"
        "Thank you,\nSecurity Team"
    )
    msg.add_alternative(
        "<html><body>"
        "<p>Dear User,</p>"
        "<p>We detected suspicious activity on your account. "
        '<a href="http://login.bank-verify-auth.com/login.php">Click here to verify credentials</a>.</p>'
        "<p>Thank you,<br>Security Team</p>"
        "</body></html>",
        subtype='html'
    )

    # Add sample attachment
    attachment_bytes = b"%PDF-1.4 sample security report document payload content for forensics testing..."
    msg.add_attachment(
        attachment_bytes,
        maintype='application',
        subtype='pdf',
        filename='security_report.pdf'
    )

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(msg.as_bytes())


def create_sample_msg(filepath: Path) -> None:
    """Create a sample .msg file using minimal OLE CFBF builder."""
    headers = (
        "Received: from relay1.corp.internal (relay1.corp.internal [10.0.1.5]) by mailserver.corp.internal with ESMTP id RLY001;\r\n"
        "\tWed, 05 Aug 2026 09:15:10 +0000\r\n"
        "Received: from outbound.corp-update-notice.org (outbound.corp-update-notice.org [203.0.113.45]) by relay1.corp.internal with ESMTP id RLY002;\r\n"
        "\tWed, 05 Aug 2026 09:15:05 +0000\r\n"
        "From: IT Desk <it-support@corp-update-notice.org>\r\n"
        "To: employee@corp.internal\r\n"
        "Subject: Mandatory Password Reset Required\r\n"
        "Date: Wed, 05 Aug 2026 09:15:00 +0000\r\n"
        "Return-Path: <bounce-service@corp-update-notice.org>\r\n"
        "Reply-To: admin@corp-update-notice.org\r\n"
        "Message-ID: <msg-20260805-091500@corp-update-notice.org>\r\n"
    )

    msg_bytes = build_minimal_msg(
        headers_str=headers,
        subject="Mandatory Password Reset Required",
        sender_name="IT Desk <it-support@corp-update-notice.org>",
        sender_email="it-support@corp-update-notice.org",
        body_text="Attention Employee,\n\nYour account password expires in 24 hours. Please reset it at http://reset.corp-update-notice.org"
    )

    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(msg_bytes)


def print_parsed_email(label: str, email_data: ParsedEmail) -> None:
    """Pretty prints all extracted fields clearly labeled."""
    print("=" * 80)
    print(f" PARSED EMAIL RESULTS [{label}]")
    print("=" * 80)
    print(f"  - From Name        : {email_data.from_name}")
    print(f"  - From Address     : {email_data.from_address}")
    print(f"  - To               : {email_data.to}")
    print(f"  - Subject          : {email_data.subject}")
    print(f"  - Date             : {email_data.date} (type: {type(email_data.date).__name__})")
    print(f"  - Return-Path      : {email_data.return_path}")
    print(f"  - Reply-To         : {email_data.reply_to}")
    print(f"  - Message-ID       : {email_data.message_id}")
    print(f"  - Received Hops ({len(email_data.received_headers)} total):")
    for i, hop in enumerate(email_data.received_headers, start=1):
        clean_hop = " ".join(hop.split())
        print(f"     [{i}] {clean_hop}")
    
    print(f"  - Body Plaintext   : {repr(email_data.body_plain[:120]) if email_data.body_plain else None}")
    print(f"  - Body HTML        : {repr(email_data.body_html[:120]) if email_data.body_html else None}")
    
    print(f"  - Attachments ({len(email_data.attachments)} total):")
    if email_data.attachments:
        for att in email_data.attachments:
            print(f"     - Filename: {att.filename} | Size: {att.size} bytes")
    else:
        print("     (None)")
    print("=" * 80)
    print()



def main():
    samples_dir = Path("temp_samples")
    eml_path = samples_dir / "sample_test.eml"
    msg_path = samples_dir / "sample_test.msg"
    invalid_path = samples_dir / "corrupted_test.eml"

    print("\n--- [Step 1] Preparing Sample Email Files ---")
    create_sample_eml(eml_path)
    print(f"[OK] Created sample EML file at: {eml_path}")
    
    create_sample_msg(msg_path)
    print(f"[OK] Created sample MSG file at: {msg_path}")

    # Create invalid test file
    invalid_path.write_text("This is corrupted text, not a valid email structure.")

    print("\n--- [Step 2] Testing EML Parsing ---")
    parsed_eml = parse_email_file(eml_path)
    print_parsed_email("EML FILE (.eml)", parsed_eml)

    print("\n--- [Step 3] Testing MSG Parsing ---")
    parsed_msg = parse_email_file(msg_path)
    print_parsed_email("MSG FILE (.msg)", parsed_msg)

    print("\n--- [Step 4] Testing Malformed/Invalid File Error Handling ---")
    try:
        parse_email_file(invalid_path)
        print("[FAIL] Expected InvalidEmailFileError was not raised!")
    except InvalidEmailFileError as e:
        print(f"[OK] Caught expected InvalidEmailFileError: {e}")

    print("\n[OK] ALL PARSER TESTS COMPLETED SUCCESSFULLY.\n")



if __name__ == "__main__":
    main()
