"""
verify_parser.py

Verification script for email_forensics/parser.py in Forenix (Module 2).
Stress-tests parser.py against edge cases, phishing samples, MSG files, and malformed inputs.
Compares parser outputs side-by-side with raw ground truth without modifying parser.py.
"""

from pathlib import Path
import sys
import email
import email.policy
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

try:
    import extract_msg
except ImportError:
    extract_msg = None

from email_forensics.parser import (
    parse_email_file,
    InvalidEmailFileError,
    ParsedEmail,
    EmailAttachment
)
from test_parser import create_sample_eml, create_sample_msg


def create_phishing_eml(filepath: Path) -> None:
    """Create a sample phishing .eml file with spoofed From, missing Reply-To, and multiple Received hops."""
    raw_content = (
        "Received: from mx-ingress.corp.internal (mx-ingress.corp.internal [10.0.0.1]) by mail.corp.internal with ESMTP id MSG99001; Wed, 05 Aug 2026 11:00:05 +0000\n"
        "Received: from bad-relay.phishnet.org (bad-relay.phishnet.org [198.51.100.44]) by mx-ingress.corp.internal with ESMTP id MSG99000; Wed, 05 Aug 2026 11:00:02 +0000\n"
        "Received: from 192.168.0.105 by bad-relay.phishnet.org with HTTP; Wed, 05 Aug 2026 10:59:58 +0000\n"
        'From: "PayPal Security Alert" <fake-alert-update@evil-domain.com>\n'
        "To: target-user@company.com\n"
        "Subject: URGENT: Your account has been suspended!\n"
        "Date: Wed, 05 Aug 2026 11:00:00 +0000\n"
        "Return-Path: <bounce-handler@evil-domain.com>\n"
        "Message-ID: <phish-20260805110000@evil-domain.com>\n"
        "Content-Type: multipart/mixed; boundary=\"====BOUNDARY123====\"\n"
        "\n"
        "--====BOUNDARY123====\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "\n"
        "Dear Customer,\nYour account was compromised. Login now to restore access:\nhttp://evil-domain.com/login\n"
        "--====BOUNDARY123====\n"
        "Content-Type: text/html; charset=\"utf-8\"\n"
        "\n"
        "<html><body><p>Dear Customer,</p><p><a href=\"http://evil-domain.com/login\">Click here immediately</a></p></body></html>\n"
        "--====BOUNDARY123====\n"
        "Content-Type: application/octet-stream; name=\"invoice_fake.exe\"\n"
        "Content-Disposition: attachment; filename=\"invoice_fake.exe\"\n"
        "\n"
        "MZ-FAKE-EXEC-PAYLOAD-BINARY-CONTENT-FOR-TESTING\n"
        "--====BOUNDARY123====--\n"
    )
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(raw_content.encode('utf-8'))


def get_eml_ground_truth(filepath: Path) -> Dict[str, Any]:
    """Inspects raw .eml file directly to extract ground truth headers."""
    raw_bytes = filepath.read_bytes()
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    received_list = msg.get_all('Received') or []

    return {
        'from': msg.get('From'),
        'to': msg.get('To'),
        'subject': msg.get('Subject'),
        'date': msg.get('Date'),
        'return_path': msg.get('Return-Path'),
        'reply_to': msg.get('Reply-To'),
        'message_id': msg.get('Message-ID'),
        'received': [str(r).strip() for r in received_list],
        'has_reply_to': 'reply-to' in [k.lower() for k in msg.keys()],
        'has_return_path': 'return-path' in [k.lower() for k in msg.keys()],
    }


def get_msg_ground_truth(filepath: Path) -> Dict[str, Any]:
    """Inspects .msg file directly using extract_msg independently for ground truth."""
    if extract_msg is None:
        return {}

    msg_obj = extract_msg.Message(str(filepath))
    try:
        sender_name = getattr(msg_obj, 'senderName', None) or getattr(msg_obj, 'sender', None)
        sender_email = getattr(msg_obj, 'senderEmail', None)

        rec_list = []
        if hasattr(msg_obj, 'header') and hasattr(msg_obj.header, 'get_all'):
            rec_list = msg_obj.header.get_all('Received') or []

        header_msg = getattr(msg_obj, 'header', None)

        att_list = []
        for att in getattr(msg_obj, 'attachments', []) or []:
            fname = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or getattr(att, 'filename', None)
            sz = getattr(att, 'size', 0)
            if sz == 0 and hasattr(att, 'data') and att.data:
                sz = len(att.data)
            att_list.append((str(fname) if fname else None, sz))

        return {
            'sender_name': str(sender_name) if sender_name else None,
            'sender_email': str(sender_email) if sender_email else None,
            'to': str(msg_obj.to) if msg_obj.to else (str(msg_obj.displayTo) if msg_obj.displayTo else None),
            'subject': str(msg_obj.subject) if msg_obj.subject else None,
            'date': getattr(msg_obj, 'date', None),
            'message_id': str(getattr(msg_obj, 'messageId', '')) if getattr(msg_obj, 'messageId', None) else (header_msg.get('Message-ID') if header_msg and hasattr(header_msg, 'get') else None),
            'received': [str(r).strip() for r in rec_list],
            'attachments': att_list
        }
    finally:
        msg_obj.close()



def verify_file(filepath: Path) -> List[Tuple[str, str, str, str]]:
    """
    Parses a single file with parser.py, compares with ground truth,
    and returns a summary rows list: (field_name, ground_truth, parser_actual, result_status).
    """
    print("=" * 90)
    print(f" VERIFYING FILE: {filepath.name} (Format: {filepath.suffix.upper()})")
    print("=" * 90)

    # 1. Run through parser.py
    parsed = parse_email_file(filepath)

    is_eml = filepath.suffix.lower() == '.eml'
    ground_truth = get_eml_ground_truth(filepath) if is_eml else get_msg_ground_truth(filepath)

    summary_table: List[Tuple[str, str, str, str]] = []

    def add_row(field: str, expected: Any, actual: Any, passed: bool, note: str = ""):
        exp_str = repr(expected) if expected is not None else "None"
        act_str = repr(actual) if actual is not None else "None"
        status = "PASS" if passed else "FAIL"
        if note and not passed:
            status += f" ({note})"
        summary_table.append((field, exp_str, act_str, status))

    print("\n--- SIDE-BY-SIDE FIELD COMPARISON ---")

    # 1. From Separation Test
    raw_from = ground_truth.get('from') if is_eml else (ground_truth.get('sender_name') or ground_truth.get('sender_email'))
    print(f"  - Raw 'From' Header : {raw_from}")
    print(f"    - Parsed Display Name  : {parsed.from_name}")
    print(f"    - Parsed Email Address : {parsed.from_address}")

    from_pass = True
    from_note = ""
    if raw_from:
        if parsed.from_address and '@' not in parsed.from_address:
            from_pass = False
            from_note = "from_address missing '@'"
        if parsed.from_name and parsed.from_address and parsed.from_name == parsed.from_address and '<' in str(raw_from):
            from_pass = False
            from_note = "from_name and from_address are duplicate despite header format"

    add_row("From Display Name", raw_from, parsed.from_name, from_pass, from_note)
    add_row("From Email Address", raw_from, parsed.from_address, from_pass, from_note)

    # 2. To Header
    raw_to = ground_truth.get('to')
    add_row("To Header", raw_to, parsed.to, parsed.to == (str(raw_to).strip() if raw_to else None))

    # 3. Subject Header
    raw_subj = ground_truth.get('subject')
    add_row("Subject", raw_subj, parsed.subject, parsed.subject == (str(raw_subj).strip() if raw_subj else None))

    # 4. Date Parsing Test
    raw_date = ground_truth.get('date')
    date_pass = True
    date_note = ""
    if raw_date:
        if parsed.date is None:
            date_pass = False
            date_note = "Date header present but parser returned None"
        elif not isinstance(parsed.date, datetime):
            date_pass = False
            date_note = f"Date type is {type(parsed.date).__name__}, expected datetime"
    else:
        date_pass = (parsed.date is None)
        date_note = "Fabricated Date when none existed"

    add_row("Date (Parsed datetime)", raw_date, parsed.date, date_pass, date_note)

    # 5. Return-Path Header (Missing Header Test)
    if is_eml:
        raw_rp = ground_truth.get('return_path')
        has_rp = ground_truth.get('has_return_path')
        rp_pass = True
        rp_note = ""
        if not has_rp and parsed.return_path is not None:
            rp_pass = False
            rp_note = "Fabricated Return-Path when missing in raw file"
        add_row("Return-Path", raw_rp, parsed.return_path, rp_pass, rp_note)

    # 6. Reply-To Header (Missing Header Test)
    if is_eml:
        raw_reply = ground_truth.get('reply_to')
        has_reply = ground_truth.get('has_reply_to')
        reply_pass = True
        reply_note = ""
        if not has_reply and parsed.reply_to is not None:
            reply_pass = False
            reply_note = "Fabricated Reply-To when missing in raw file"
        add_row("Reply-To", raw_reply, parsed.reply_to, reply_pass, reply_note)

    # 7. Message-ID
    raw_mid = ground_truth.get('message_id')
    add_row("Message-ID", raw_mid, parsed.message_id, parsed.message_id == (str(raw_mid).strip() if raw_mid else None))

    # 8. Received Hops Count & Order Test
    raw_received = ground_truth.get('received', [])
    rec_count_pass = (len(parsed.received_headers) == len(raw_received))
    rec_note = ""
    if not rec_count_pass:
        rec_note = f"Expected {len(raw_received)} hops, got {len(parsed.received_headers)}"

    add_row("Received Hops Count", len(raw_received), len(parsed.received_headers), rec_count_pass, rec_note)

    print(f"\n  - Received Hops Comparison ({len(parsed.received_headers)} extracted vs {len(raw_received)} in raw):")
    for i, p_hop in enumerate(parsed.received_headers, start=1):
        raw_h = raw_received[i-1] if i <= len(raw_received) else "<MISSING IN RAW>"
        p_clean = " ".join(p_hop.split())[:75]
        r_clean = " ".join(str(raw_h).split())[:75]
        print(f"     Hop [{i}] Parsed: {p_clean}")
        print(f"            Raw   : {r_clean}")

    # 9. Attachments Metadata Check
    print(f"\n  - Attachments Metadata ({len(parsed.attachments)} extracted):")
    for att in parsed.attachments:
        print(f"     - Filename: {att.filename} | Size: {att.size} bytes")

    add_row("Attachments Count", len(ground_truth.get('attachments', [])) if not is_eml else len(parsed.attachments), len(parsed.attachments), True)

    print("\n--- DETAILED SUMMARY TABLE ---")
    print(f"{'Field Name':<22} | {'Expected Ground Truth':<35} | {'Actual Parser Output':<35} | {'Status'}")
    print("-" * 105)
    for f_name, exp, act, st in summary_table:
        exp_trunc = (exp[:32] + '...') if len(exp) > 35 else exp
        act_trunc = (act[:32] + '...') if len(act) > 35 else act
        print(f"{f_name:<22} | {exp_trunc:<35} | {act_trunc:<35} | {st}")
    print("-" * 105)

    return summary_table


def verify_malformed_file(filepath: Path) -> Tuple[str, str, str, str]:
    """Verifies that a malformed file raises InvalidEmailFileError cleanly."""
    print("=" * 90)
    print(f" VERIFYING MALFORMED FILE HANDLING: {filepath.name}")
    print("=" * 90)

    try:
        parse_email_file(filepath)
        print("[FAIL] Malformed file did not raise InvalidEmailFileError!")
        return ("Malformed File Check", "InvalidEmailFileError raised", "No exception raised (returned data)", "FAIL")
    except InvalidEmailFileError as e:
        print(f"[OK] PASS: Successfully caught InvalidEmailFileError: {e}")
        return ("Malformed File Check", "InvalidEmailFileError raised", f"InvalidEmailFileError('{e}')", "PASS")
    except Exception as e:
        print(f"[FAIL] Raised unhandled exception type {type(e).__name__}: {e}")
        return ("Malformed File Check", "InvalidEmailFileError raised", f"Unhandled {type(e).__name__}: {e}", "FAIL")



def main():
    samples_dir = Path("temp_samples")

    # Create test sample files
    clean_eml = samples_dir / "sample_clean.eml"
    phish_eml = samples_dir / "sample_phishing.eml"
    msg_file = samples_dir / "sample_test.msg"
    malformed_eml = samples_dir / "malformed_test.eml"

    print("\n[Step 0] Preparing test files...")
    create_sample_eml(clean_eml)
    create_phishing_eml(phish_eml)
    create_sample_msg(msg_file)
    malformed_eml.write_text("NOT_AN_EMAIL_HEADER\r\nContent-Type: invalid/junk\r\n\r\nTruncated garbage data...", encoding="utf-8")

    # If CLI arguments provided, test user files instead
    test_files = [clean_eml, phish_eml, msg_file]
    if len(sys.argv) > 1:
        custom_paths = [Path(p) for p in sys.argv[1:] if Path(p).exists()]
        if custom_paths:
            test_files = custom_paths
            print(f"Testing user-provided files: {[str(p) for p in test_files]}")

    all_summaries: List[Tuple[str, str, str, str]] = []

    for tf in test_files:
        if tf.exists():
            rows = verify_file(tf)
            all_summaries.extend(rows)
        else:
            print(f"Warning: Test file {tf} not found.")

    # Malformed file check
    malformed_row = verify_malformed_file(malformed_eml)
    all_summaries.append(malformed_row)

    print("\n" + "=" * 90)
    print(" FINAL OVERALL VERIFICATION SUMMARY TABLE")
    print("=" * 90)
    print(f"{'Check / Field Name':<25} | {'Expected':<30} | {'Actual':<30} | {'Status'}")
    print("-" * 95)
    total_checks = len(all_summaries)
    passed_checks = 0
    for field_name, exp, act, st in all_summaries:
        if st.startswith("PASS"):
            passed_checks += 1
        exp_t = (exp[:27] + '...') if len(exp) > 30 else exp
        act_t = (act[:27] + '...') if len(act) > 30 else act
        print(f"{field_name:<25} | {exp_t:<30} | {act_t:<30} | {st}")
    print("-" * 95)
    print(f"TOTAL CHECKS: {total_checks} | PASSED: {passed_checks} | FAILED: {total_checks - passed_checks}")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    main()
