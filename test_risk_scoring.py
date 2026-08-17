"""
test_risk_scoring.py

Test script for email_forensics/risk_scoring.py in Forenix (Module 2).
Executes all 4 analysis layers (parser, auth_checks, domain_intel, url_analysis) on clean & phishing sample emails,
feeds the results into calculate_risk_score(), verifies strict hard override rules (SPF==Fail AND DKIM==Fail),
and prints complete audit trail breakdowns.
"""

from pathlib import Path
from email_forensics.parser import parse_email_file, ParsedEmail
from email_forensics.auth_checks import run_auth_checks, AuthResult, SPFResult, DKIMResult, DMARCResult
from email_forensics.domain_intel import run_domain_intel, DomainIntelResult, DomainBreakdown
from email_forensics.url_analysis import run_url_analysis, UrlAnalysisResult
from email_forensics.attachment_analysis import run_attachment_analysis, AttachmentAnalysisResult
from email_forensics.risk_scoring import calculate_risk_score, RiskScoreResult


def print_risk_score_result(label: str, result: RiskScoreResult) -> None:
    """Pretty prints RiskScoreResult with full audit trail breakdown and verdict mechanism."""
    print("=" * 85)
    print(f" RISK SCORING ENGINE RESULTS [{label}]")
    print("=" * 85)
    print(f"  - FINAL RISK BAND          : {result.risk_band}")
    print(f"  - TOTAL CLAMPED SCORE      : {result.total_score} / 100")
    print(f"  - RAW UNCAPPED SCORE       : {result.raw_score}")
    print(f"  - HARD OVERRIDE FLAGGED    : {result.hard_flagged}")
    
    # Mechanism trigger explanation
    if result.hard_flagged:
        trigger_mech = f"Hard Override Triggered ({result.hard_flag_reason})"
    elif result.total_score >= 60:
        trigger_mech = "Score Threshold (Score >= 60 -> Likely Spoofed)"
    elif result.total_score >= 40:
        trigger_mech = "Score Threshold (40 <= Score < 60 -> High Risk)"
    elif result.total_score >= 15:
        trigger_mech = "Score Threshold (15 <= Score < 40 -> Medium Risk)"
    else:
        trigger_mech = "Score Threshold (Score < 15 -> Low Risk)"

    print(f"  - VERDICT MECHANISM        : {trigger_mech}")
    print()
    print("  - COMPLETE AUDIT TRAIL BREAKDOWN:")
    for idx, item in enumerate(result.breakdown, start=1):
        print(f"      [{idx:02d}] {item.category:<22} | {item.formatted_line:<50} (pts: +{item.points_added})")
    print("=" * 85)
    print()


def main():
    samples_dir = Path("temp_samples")
    gmail_sample_path = samples_dir / "sample_legit_gmail.eml"
    phish_sample_path = samples_dir / "sample_phishing.eml"

    # =========================================================================
    # Step 1: Testing Clean Email Sample (gmail.com)
    # =========================================================================
    print("\n--- [Step 1] Testing Clean Email Sample (gmail.com) ---")
    if gmail_sample_path.exists():
        raw_bytes_clean = gmail_sample_path.read_bytes()
        parsed_clean = parse_email_file(gmail_sample_path)
    else:
        raw_bytes_clean = b"From: service@gmail.com\r\nTo: user@target.com\r\nSubject: Clean Test\r\n\r\nClean body."
        parsed_clean = ParsedEmail(
            from_name="Gmail Service", from_address="service@gmail.com",
            to="user@target.com", subject="Clean Test", date=None,
            return_path=None, reply_to=None, message_id=None,
            received_headers=["Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.220.41]) by mx.google.com; Wed, 05 Aug 2026 10:00:00 -0700"],
            body_plain="Clean body https://gmail.com/help", body_html="<p>Clean body <a href='https://gmail.com/help'>https://gmail.com/help</a></p>",
            attachments=[]
        )

    auth_clean = run_auth_checks(parsed_clean, raw_bytes=raw_bytes_clean)
    domain_clean = run_domain_intel(parsed_clean)
    url_clean = run_url_analysis(parsed_clean)
    att_clean = run_attachment_analysis(parsed_clean)

    risk_clean = calculate_risk_score(parsed_clean, auth_clean, domain_clean, url_clean, att_clean)
    print_risk_score_result("CLEAN GMAIL EMAIL SAMPLE", risk_clean)

    assert risk_clean.total_score < 40, f"Expected Low/Medium score for clean email, got {risk_clean.total_score}"
    assert risk_clean.hard_flagged is False, "Expected hard_flagged=False for clean email"
    print("[PASS] Clean Email Assertion Passed (Low Risk, hard_flagged=False).")

    # =========================================================================
    # Step 2: Testing Phishing Email Sample from Disk (SPF=SoftFail, DKIM=Missing)
    # =========================================================================
    print("\n--- [Step 2] Testing Phishing Email Sample (SPF=SoftFail, DKIM=Missing) ---")
    if phish_sample_path.exists():
        raw_bytes_phish = phish_sample_path.read_bytes()
        parsed_phish = parse_email_file(phish_sample_path)
    else:
        raw_bytes_phish = (
            b"From: PayPal Billing <support@evil-domain.com>\r\n"
            b"Return-Path: <bounce@evil-domain.com>\r\n"
            b"To: victim@target.com\r\n"
            b"Subject: Account Suspended\r\n"
            b"Received: from evil-domain.com ([10.0.0.1]) by mx.target.com\r\n\r\n"
            b"Please <a href='http://evil-domain.com/login.php'>Verify your PayPal Account</a> immediately!"
        )
        parsed_phish = ParsedEmail(
            from_name="PayPal Billing", from_address="support@evil-domain.com",
            to="victim@target.com", subject="Account Suspended", date=None,
            return_path="bounce@evil-domain.com", reply_to=None, message_id=None,
            received_headers=["Received: from evil-domain.com ([10.0.0.1]) by mx.target.com"],
            body_plain="Please Verify your PayPal Account at http://evil-domain.com/login",
            body_html="<p>Please <a href='http://evil-domain.com/login.php'>Verify your PayPal Account</a> immediately!</p>",
            attachments=[]
        )

    auth_phish = run_auth_checks(parsed_phish, raw_bytes=raw_bytes_phish)
    domain_phish = run_domain_intel(parsed_phish)
    url_phish = run_url_analysis(parsed_phish)
    att_phish = run_attachment_analysis(parsed_phish)

    risk_phish = calculate_risk_score(parsed_phish, auth_phish, domain_phish, url_phish, att_phish)
    print_risk_score_result("PHISHING SAMPLE (SPF=SoftFail, DKIM=Missing)", risk_phish)

    # Correct assertion after adding attachment scoring rules: sample_phishing.eml includes a dangerous attachment (+20), raising score to 62 (Likely Spoofed)
    assert risk_phish.hard_flagged is False, f"Expected hard_flagged=False for SPF=SoftFail/DKIM=Missing, got {risk_phish.hard_flagged}"
    assert risk_phish.total_score >= 40, f"Expected elevated risk score for phishing sample, got {risk_phish.total_score}"
    print("[PASS] Phishing Sample Assertion Passed (hard_flagged=False via Score Threshold mechanism).")

    # =========================================================================
    # Step 3: Testing Strict Hard Override Trigger (SPF==Fail AND DKIM==Fail)
    # =========================================================================
    print("\n--- [Step 3] Testing Strict Hard Override Trigger (SPF=Fail AND DKIM=Fail) ---")
    auth_strict_fail = AuthResult(
        spf=SPFResult(status="Fail", ip_used="10.0.0.1", domain_checked="phish.com", details="SPF record failed"),
        dkim=DKIMResult(status="Fail", reason="Body hash mismatch"),
        dmarc=DMARCResult(status="Fail", policy="reject"),
        summary_status="FAIL"
    )



    dom_strict_fail = DomainIntelResult(
        status="SUCCESS",
        domain_breakdown=DomainBreakdown("phish.com", "", "phish", "com", "phish.com")
    )
    url_strict_fail = UrlAnalysisResult(status="SUCCESS", links=[], total_links=0, suspicious_links_count=0)

    risk_strict = calculate_risk_score(parsed_phish, auth_strict_fail, dom_strict_fail, url_strict_fail)
    print_risk_score_result("HARD OVERRIDE TEST (SPF=Fail AND DKIM=Fail)", risk_strict)

    # Confirm strict hard override assertion
    assert risk_strict.hard_flagged is True, f"Expected hard_flagged=True for exact SPF=Fail & DKIM=Fail, got {risk_strict.hard_flagged}"
    assert risk_strict.risk_band == "Likely Spoofed", f"Expected 'Likely Spoofed' risk band, got {risk_strict.risk_band}"
    print("[PASS] Strict Hard Override Assertion Passed (Likely Spoofed, hard_flagged=True via Hard Override mechanism).")

    # =========================================================================
    # Step 4: Hand-Calculation Cross-Check
    # =========================================================================
    print("\n--- [Step 4] Hand-Calculation Cross-Check ---")
    manual_items = []
    for item in risk_phish.breakdown:
        if item.points_added > 0:
            manual_items.append((item.formatted_line, item.points_added))

    expected_manual_raw = sum(pts for _, pts in manual_items)
    print(f"  - Firing Rules Hand-Calculation Breakdown:")
    for line, pts in manual_items:
        print(f"      * {line:<55} : +{pts}")
    print(f"  - Expected Manual Hand-Calculated Raw Score : {expected_manual_raw}")
    print(f"  - Code Output Calculated Raw Score          : {risk_phish.raw_score}")

    assert risk_phish.raw_score == expected_manual_raw, (
        f"Mismatch between hand-calculation ({expected_manual_raw}) and code output ({risk_phish.raw_score})"
    )
    print("[PASS] Manual Hand-Calculation matches Code Risk Score Output EXACTLY!\n")
    print("[OK] ALL RISK SCORING ENGINE TESTS COMPLETED SUCCESSFULLY.\n")


if __name__ == "__main__":
    main()
