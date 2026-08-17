"""
Email Forensics module for Forenix.
Provides file parsing for .eml and .msg files into a unified internal data structure.
"""

from .parser import (
    EmailParserError,
    InvalidEmailFileError,
    EmailAttachment,
    ParsedEmail,
    parse_email_file,
    parse_eml,
    parse_msg,
)

from .auth_checks import (
    SPFResult,
    DKIMResult,
    DMARCResult,
    AuthResult,
    extract_topmost_received_ip,
    check_spf,
    check_dkim,
    check_dmarc,
    run_auth_checks,
)

from .domain_intel import (
    DomainBreakdown,
    DomainIntelResult,
    parse_domain_structure,
    detect_homograph,
    detect_typosquat,
    run_domain_intel,
)

from .url_analysis import (
    ExtractedLink,
    UrlAnalysisResult,
    extract_links_from_html,
    extract_links_from_plaintext,
    analyze_single_link,
    run_url_analysis,
)

from .attachment_analysis import (
    AttachmentAnalysisItem,
    AttachmentAnalysisResult,
    run_attachment_analysis,
)

from .risk_scoring import (
    ScoreBreakdownItem,
    RiskScoreResult,
    calculate_risk_score,
)

from .routes import email_bp

__all__ = [
    "EmailParserError",
    "InvalidEmailFileError",
    "EmailAttachment",
    "ParsedEmail",
    "parse_email_file",
    "parse_eml",
    "parse_msg",
    "SPFResult",
    "DKIMResult",
    "DMARCResult",
    "AuthResult",
    "extract_topmost_received_ip",
    "check_spf",
    "check_dkim",
    "check_dmarc",
    "run_auth_checks",
    "DomainBreakdown",
    "DomainIntelResult",
    "parse_domain_structure",
    "detect_homograph",
    "detect_typosquat",
    "run_domain_intel",
    "ExtractedLink",
    "UrlAnalysisResult",
    "extract_links_from_html",
    "extract_links_from_plaintext",
    "analyze_single_link",
    "run_url_analysis",
    "AttachmentAnalysisItem",
    "AttachmentAnalysisResult",
    "run_attachment_analysis",
    "ScoreBreakdownItem",
    "RiskScoreResult",
    "calculate_risk_score",
    "email_bp",
]





