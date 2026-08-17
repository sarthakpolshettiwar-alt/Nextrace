"""
test_domain_intel.py

Test script for email_forensics/domain_intel.py in Forenix (Module 2).
Tests domain structure parsing via tldextract, homograph/punycode detection via idna & unicodedata,
typosquatting detection via rapidfuzz against brand_domains.json, and invalid domain handling.
"""

import idna
from pathlib import Path
from email_forensics.parser import ParsedEmail
from email_forensics.domain_intel import (
    run_domain_intel,
    DomainIntelResult,
    parse_domain_structure,
    detect_homograph,
    detect_typosquat,
    load_brand_domains
)


def print_intel_result(label: str, result: DomainIntelResult) -> None:
    """Pretty prints every field of DomainIntelResult clearly labeled."""
    print("=" * 85)
    print(f" DOMAIN INTELLIGENCE RESULTS [{label}]")
    print("=" * 85)
    print(f"  - STATUS                   : {result.status}")
    
    if result.domain_breakdown:
        bd = result.domain_breakdown
        print("  - Domain Structure Breakdown (tldextract):")
        print(f"      * Raw Domain           : {bd.raw_domain}")
        print(f"      * Subdomain            : {bd.subdomain or '(none)'}")
        print(f"      * Domain Label         : {bd.domain}")
        print(f"      * Public Suffix (TLD)  : {bd.suffix}")
        print(f"      * Registered Domain    : {bd.registered_domain}")
    else:
        print("  - Domain Structure Breakdown : (None)")

    print()
    print("  - Homograph / Punycode Analysis:")
    print(f"      * Is Homograph Flagged : {result.is_homograph}")
    clean_homo_details = result.homograph_details.encode('ascii', errors='backslashreplace').decode('ascii') if result.homograph_details else '(none)'
    print(f"      * Details              : {clean_homo_details}")


    print()
    print("  - Typosquatting Analysis (Levenshtein Distance):")
    print(f"      * Is Typosquat Flagged : {result.is_typosquat}")
    print(f"      * Matched Brand Domain : {result.typosquat_matched_brand or '(none)'}")
    print(f"      * Levenshtein Distance : {result.typosquat_distance if result.typosquat_distance is not None else '(none)'}")
    print(f"      * Details              : {result.typosquat_details or '(none)'}")
    print("=" * 85)
    print()


def main():
    print("\n--- [Step 1] Loading Monitored Brand Domains ---")
    brands = load_brand_domains()
    print(f"[OK] Loaded {len(brands)} monitored brand domains for typosquat analysis.")

    # Test Case 1: Clean Domain (paypal.com)
    print("\n--- [Step 2] Testing Clean Domain (paypal.com) ---")
    email_clean = ParsedEmail(
        from_name="PayPal Support",
        from_address="service@paypal.com",
        to="user@target.com",
        subject="Your Account Statement",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[], body_plain=None, body_html=None, attachments=[]
    )
    res_clean = run_domain_intel(email_clean)
    print_intel_result("CLEAN DOMAIN (paypal.com)", res_clean)

    # Test Case 2: Typosquat Domain (paypa1.com & paypa1-secure.com)
    print("\n--- [Step 3] Testing Typosquat Domain (paypa1-secure.com) ---")
    email_typosquat = ParsedEmail(
        from_name="PayPal Billing",
        from_address="billing@paypa1-secure.com",
        to="user@target.com",
        subject="Security Notice",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[], body_plain=None, body_html=None, attachments=[]
    )
    res_typosquat = run_domain_intel(email_typosquat)
    print_intel_result("TYPOSQUAT DOMAIN (paypa1-secure.com)", res_typosquat)

    # Test Case 3: Punycode / Homograph Domain (Cyrillic 'а' encoded to IDNA punycode)
    # Constructing "pаypal.com" where 'а' is Cyrillic \u0430
    cyrillic_paypal = "p\u0430ypal.com"
    punycode_paypal = idna.encode(cyrillic_paypal).decode('ascii')
    print(f"\n--- [Step 4] Testing Punycode Homograph Domain ({punycode_paypal}) ---")
    email_homograph = ParsedEmail(
        from_name="Security Team",
        from_address=f"alert@{punycode_paypal}",
        to="user@target.com",
        subject="Action Required",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[], body_plain=None, body_html=None, attachments=[]
    )
    res_homograph = run_domain_intel(email_homograph)
    print_intel_result(f"PUNYCODE HOMOGRAPH ({punycode_paypal})", res_homograph)

    # Test Case 4: Complex Multi-part Subdomain (paypal.com.security-check.ru)
    print("\n--- [Step 5] Testing Complex Multi-part Subdomain Structure ---")
    email_complex = ParsedEmail(
        from_name="Fake Paypal",
        from_address="login@paypal.com.security-check.ru",
        to="user@target.com",
        subject="Verify Account",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[], body_plain=None, body_html=None, attachments=[]
    )
    res_complex = run_domain_intel(email_complex)
    print_intel_result("COMPLEX SUBDOMAIN (paypal.com.security-check.ru)", res_complex)

    # Test Case 6: Invalid / Missing Sender Domain
    print("\n--- [Step 6] Testing Invalid / Missing Sender Domain Edge Case ---")
    email_invalid = ParsedEmail(
        from_name="Anonymous",
        from_address=None,
        to="user@target.com",
        subject="No Sender Email",
        date=None, return_path=None, reply_to=None, message_id=None,
        received_headers=[], body_plain=None, body_html=None, attachments=[]
    )
    res_invalid = run_domain_intel(email_invalid)
    print_intel_result("INVALID / MISSING SENDER DOMAIN", res_invalid)

    print("[OK] ALL DOMAIN INTELLIGENCE TESTS COMPLETED SUCCESSFULLY.\n")


if __name__ == "__main__":
    main()
