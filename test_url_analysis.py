"""
test_url_analysis.py

Test script for email_forensics/url_analysis.py in Forenix (Module 2).
Tests link extraction from HTML & Plaintext bodies, domain mismatch detection, brand impersonation,
raw IP destinations, URL shorteners, destination typosquats, and empty-link edge cases.
"""

from pathlib import Path
from email_forensics.parser import parse_email_file, ParsedEmail
from email_forensics.url_analysis import run_url_analysis, UrlAnalysisResult


def print_url_analysis_result(label: str, result: UrlAnalysisResult) -> None:
    """Pretty prints every field of UrlAnalysisResult clearly labeled for manual verification."""
    print("=" * 85)
    print(f" URL & LINK ANALYSIS RESULTS [{label}]")
    print("=" * 85)
    print(f"  - STATUS                   : {result.status}")
    print(f"  - TOTAL LINKS EXTRACTED    : {result.total_links}")
    print(f"  - SUSPICIOUS LINKS COUNT   : {result.suspicious_links_count}")
    print()

    if not result.links:
        print("  - Extracted Links          : (None - No links present in email)")
    else:
        print("  - Extracted Links Detail:")
        for idx, link in enumerate(result.links, start=1):
            disp_text = (link.link_text[:50] + '...') if len(link.link_text) > 53 else link.link_text
            disp_dest = (link.destination_url[:50] + '...') if len(link.destination_url) > 53 else link.destination_url
            
            print(f"     [{idx}] Link Text       : {disp_text}")
            print(f"         Destination URL : {disp_dest}")
            print(f"         Text Domain     : {link.text_domain or '(none)'}")
            print(f"         Dest Domain     : {link.destination_domain or '(none)'}")
            print(f"         Is Mismatch     : {link.is_mismatch}")
            print(f"         Brand Imperson. : {link.is_brand_impersonation}")
            print(f"         Is Raw IP       : {link.is_raw_ip}")
            print(f"         Is Shortened    : {link.is_shortened}")
            print(f"         Is Typosquat    : {link.is_typosquat}")
            print(f"         Is Homograph    : {link.is_homograph}")
            print(f"         Flags Raised    : {len(link.flags)}")
            for f_idx, flag in enumerate(link.flags, start=1):
                print(f"            ({f_idx}) {flag}")
            print(f"         Details         : {link.details}")
            print()

    print("=" * 85)
    print()


def main():
    samples_dir = Path("temp_samples")
    phish_path = samples_dir / "sample_phishing.eml"

    # Test Case 1: Clean Email Link (Text and Href match)
    print("\n--- [Step 1] Testing Clean Email Link (Matching Text & Destination) ---")
    clean_email = ParsedEmail(
        from_name="PayPal Support",
        from_address="service@paypal.com",
        to="user@target.com",
        subject="Account Update Confirmation",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Please visit https://paypal.com/help to view your statement.",
        body_html='<html><body><p>Please visit <a href="https://paypal.com/help">https://paypal.com/help</a> to view your statement.</p></body></html>',
        attachments=[]
    )
    res_clean = run_url_analysis(clean_email)
    print_url_analysis_result("CLEAN EMAIL LINK", res_clean)

    # Test Case 2: Phishing Sample Email Link (Mismatched domain)
    print("\n--- [Step 2] Testing Phishing Sample Email Links ---")
    phish_email = ParsedEmail(
        from_name="PayPal Security Alert",
        from_address="alert@evil-domain.com",
        to="victim@target.com",
        subject="Account Suspended",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Login now at http://evil-domain.com/login",
        body_html='<html><body><p>Please <a href="http://evil-domain.com/login.php">Verify your PayPal Account</a> immediately!</p></body></html>',
        attachments=[]
    )
    res_phish = run_url_analysis(phish_email)
    print_url_analysis_result("PHISHING MISMATCHED LINK", res_phish)

    # Test Case 3: Raw IP Destination Link
    print("\n--- [Step 3] Testing Raw IP Destination Link ---")
    raw_ip_email = ParsedEmail(
        from_name="IT Support",
        from_address="admin@company.com",
        to="user@target.com",
        subject="Server Maintenance",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Access server at http://198.51.100.25/login",
        body_html='<html><body><p>Access server at <a href="http://198.51.100.25/login">http://198.51.100.25/login</a></p></body></html>',
        attachments=[]
    )
    res_ip = run_url_analysis(raw_ip_email)
    print_url_analysis_result("RAW IP DESTINATION LINK", res_ip)

    # Test Case 4: URL Shortener Link
    print("\n--- [Step 4] Testing URL Shortener Link ---")
    shortener_email = ParsedEmail(
        from_name="Promo Desk",
        from_address="news@promo.com",
        to="user@target.com",
        subject="Special Deal",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Click deal link https://bit.ly/3xYz12",
        body_html='<html><body><p>Claim discount: <a href="https://bit.ly/3xYz12">https://bit.ly/3xYz12</a></p></body></html>',
        attachments=[]
    )
    res_shortener = run_url_analysis(shortener_email)
    print_url_analysis_result("URL SHORTENER LINK", res_shortener)

    # Test Case 5: Destination Typosquatting Link
    print("\n--- [Step 5] Testing Typosquat Destination Link ---")
    typo_email = ParsedEmail(
        from_name="Security Alert",
        from_address="notice@paypa1-secure.com",
        to="user@target.com",
        subject="Urgent Notice",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Reset password at http://paypa1-secure.com/reset",
        body_html='<html><body><p>Reset password at <a href="http://paypa1-secure.com/reset">http://paypa1-secure.com/reset</a></p></body></html>',
        attachments=[]
    )
    res_typo = run_url_analysis(typo_email)
    print_url_analysis_result("TYPOSQUAT DESTINATION LINK", res_typo)

    # Test Case 6: Email with No Links Edge Case
    print("\n--- [Step 6] Testing Email with No Links Edge Case ---")
    no_link_email = ParsedEmail(
        from_name="John Doe",
        from_address="john@company.com",
        to="jane@company.com",
        subject="Internal Note",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[],
        body_plain="Hello Jane, let's catch up later today. Thanks, John.",
        body_html="<html><body><p>Hello Jane, let's catch up later today. Thanks, John.</p></body></html>",
        attachments=[]
    )
    res_no_link = run_url_analysis(no_link_email)
    print_url_analysis_result("EMAIL WITH NO LINKS", res_no_link)

    print("[OK] ALL URL & LINK ANALYSIS TESTS COMPLETED SUCCESSFULLY.\n")


if __name__ == "__main__":
    main()
