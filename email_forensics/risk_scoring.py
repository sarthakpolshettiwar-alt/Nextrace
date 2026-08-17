"""
email_forensics/risk_scoring.py

Risk Scoring Engine for Forenix Module 2 (Email Forensic Analysis).
Combines outputs of ParsedEmail, AuthResult, DomainIntelResult, and UrlAnalysisResult
into a transparent, explainable risk score (0-100), risk band, hard override verdict,
and a complete audit trail breakdown list.
"""

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import logging

from .parser import ParsedEmail
from .auth_checks import AuthResult
from .domain_intel import DomainIntelResult, parse_domain_structure, is_known_esp
from .url_analysis import UrlAnalysisResult
from .attachment_analysis import AttachmentAnalysisResult
from .header_integrity import HeaderIntegrityResult
from .html_analysis import HTMLAnalysisResult
from .content_analysis import ContentAnalysisResult
from .domain_age import DomainAgeResult
from .reputation_checks import ReputationCheckResult



logger = logging.getLogger(__name__)



@dataclass
class ScoreBreakdownItem:
    """Represents a single rule evaluation line item in the forensic audit trail."""
    category: str        # 'Authentication', 'Domain Intelligence', 'URL Analysis', 'Attachment Analysis'
    rule_name: str       # e.g., 'SPF Status', 'DKIM Status', 'Link Brand Impersonation'
    state: str           # e.g., 'Fail', 'SoftFail', 'Pass', '2 links flagged'
    points_added: int    # e.g., 25, 0, 15
    formatted_line: str  # e.g., "SPF: Fail (+25)" or "DKIM: Pass (+0)"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskScoreResult:
    """Result container for Risk Scoring Engine."""
    total_score: int           # Clamped [0, 100]
    raw_score: int             # Uncapped sum of rule points
    risk_band: str             # 'Low Risk', 'Medium Risk', 'High Risk', 'Likely Spoofed'
    hard_flagged: bool
    hard_flag_reason: Optional[str]
    breakdown: List[ScoreBreakdownItem]
    verdict_explanation: str = "Email forensic evaluation complete."

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_score': self.total_score,
            'raw_score': self.raw_score,
            'risk_band': self.risk_band,
            'hard_flagged': self.hard_flagged,
            'hard_flag_reason': self.hard_flag_reason,
            'verdict_explanation': self.verdict_explanation,
            'breakdown': [b.to_dict() for b in self.breakdown]
        }



def extract_domain_from_header_address(header_val: Optional[str]) -> Optional[str]:
    """Helper to extract registered domain from email header strings like Return-Path or Reply-To."""
    if not header_val:
        return None
    bd = parse_domain_structure(header_val)
    return bd.registered_domain if bd else None


def calculate_risk_score(
    parsed_email: ParsedEmail,
    auth_result: AuthResult,
    domain_result: DomainIntelResult,
    url_result: UrlAnalysisResult,
    attachment_result: Optional[AttachmentAnalysisResult] = None,
    header_result: Optional[HeaderIntegrityResult] = None,
    html_result: Optional[HTMLAnalysisResult] = None,
    content_result: Optional[ContentAnalysisResult] = None,
    domain_age_result: Optional[DomainAgeResult] = None,
    reputation_result: Optional[ReputationCheckResult] = None
) -> RiskScoreResult:

    """
    Stateless, deterministic function that computes the forensic risk score.
    Does NOT execute external checks — performs pure arithmetic and rule evaluations on provided input objects.
    """
    breakdown: List[ScoreBreakdownItem] = []

    # =========================================================================
    # 1. AUTHENTICATION LAYER SCORING
    # =========================================================================
    # 1.1 SPF Check
    spf_status = (auth_result.spf.status if auth_result and auth_result.spf else "None").strip()
    spf_pts = 0
    if spf_status == "Fail":
        spf_pts = 25
    elif spf_status == "SoftFail":
        spf_pts = 12
    elif spf_status in ("None", "Unable to verify", "TempError", "PermError"):
        spf_pts = 8
    elif spf_status == "Pass":
        spf_pts = 0
    else:
        spf_pts = 8

    breakdown.append(ScoreBreakdownItem(
        category="Authentication",
        rule_name="SPF Status",
        state=spf_status,
        points_added=spf_pts,
        formatted_line=f"SPF Status: {spf_status} (+{spf_pts})"
    ))

    # 1.2 DKIM Check
    dkim_status = (auth_result.dkim.status if auth_result and auth_result.dkim else "Missing").strip()
    dkim_pts = 0
    if dkim_status == "Fail":
        dkim_pts = 25
    elif dkim_status in ("Missing", "Unable to verify"):
        dkim_pts = 10
    elif dkim_status == "Pass":
        dkim_pts = 0
    else:
        dkim_pts = 10

    breakdown.append(ScoreBreakdownItem(
        category="Authentication",
        rule_name="DKIM Status",
        state=dkim_status,
        points_added=dkim_pts,
        formatted_line=f"DKIM Status: {dkim_status} (+{dkim_pts})"
    ))

    # 1.3 DMARC Check
    dmarc_status = (auth_result.dmarc.status if auth_result and auth_result.dmarc else "None").strip()
    dmarc_pts = 0
    if dmarc_status == "Fail":
        dmarc_pts = 20
    elif dmarc_status in ("None", "Unable to verify"):
        dmarc_pts = 5
    elif dmarc_status == "Pass":
        dmarc_pts = 0
    else:
        dmarc_pts = 5

    breakdown.append(ScoreBreakdownItem(
        category="Authentication",
        rule_name="DMARC Status",
        state=dmarc_status,
        points_added=dmarc_pts,
        formatted_line=f"DMARC Status: {dmarc_status} (+{dmarc_pts})"
    ))

    # =========================================================================
    # 2. DOMAIN INTELLIGENCE LAYER SCORING
    # =========================================================================
    from_dom = domain_result.domain_breakdown.registered_domain if domain_result and domain_result.domain_breakdown else None

    # 2.1 Sender Typosquatting
    sender_typo_pts = 20 if (domain_result and domain_result.is_typosquat) else 0
    breakdown.append(ScoreBreakdownItem(
        category="Domain Intelligence",
        rule_name="Sender Domain Typosquatting",
        state=domain_result.typosquat_details if (domain_result and domain_result.is_typosquat) else "None",
        points_added=sender_typo_pts,
        formatted_line=f"Sender Domain Typosquatting: {domain_result.typosquat_details if (domain_result and domain_result.is_typosquat) else 'None'} (+{sender_typo_pts})"
    ))

    # 2.2 Sender Homograph / Punycode
    sender_hom_pts = 20 if (domain_result and domain_result.is_homograph) else 0
    breakdown.append(ScoreBreakdownItem(
        category="Domain Intelligence",
        rule_name="Sender Domain Homograph/Punycode",
        state=domain_result.homograph_details if (domain_result and domain_result.is_homograph) else "None",
        points_added=sender_hom_pts,
        formatted_line=f"Sender Domain Homograph/Punycode: {domain_result.homograph_details if (domain_result and domain_result.is_homograph) else 'None'} (+{sender_hom_pts})"
    ))

    # 2.3 Return-Path Alignment
    rp_domain = extract_domain_from_header_address(parsed_email.return_path)
    rp_pts = 0
    rp_state = "Aligned"

    if rp_domain and from_dom and rp_domain != from_dom:
        if is_known_esp(rp_domain):
            rp_pts = 2
            rp_state = f"Return-Path uses known ESP ({rp_domain}) — common for companies using third-party email delivery, not independently indicative of spoofing"
        else:
            rp_pts = 10
            rp_state = f"Mismatch ({rp_domain} vs {from_dom})"

    breakdown.append(ScoreBreakdownItem(
        category="Domain Intelligence",
        rule_name="Return-Path Domain Alignment",
        state=rp_state,
        points_added=rp_pts,
        formatted_line=f"Return-Path Alignment: {rp_state} (+{rp_pts})"
    ))

    # 2.4 Reply-To Alignment
    reply_domain = extract_domain_from_header_address(parsed_email.reply_to)
    reply_pts = 0
    reply_state = "Aligned"
    if reply_domain and from_dom and reply_domain != from_dom:
        reply_pts = 8
        reply_state = f"Mismatch ({reply_domain} vs {from_dom})"

    breakdown.append(ScoreBreakdownItem(
        category="Domain Intelligence",
        rule_name="Reply-To Domain Alignment",
        state=reply_state,
        points_added=reply_pts,
        formatted_line=f"Reply-To Alignment: {reply_state} (+{reply_pts})"
    ))

    # =========================================================================
    # 3. URL ANALYSIS LAYER SCORING
    # =========================================================================
    brand_impersonation_count = 0
    generic_mismatch_count = 0
    raw_ip_count = 0
    url_typo_hom_count = 0
    shortener_count = 0

    if url_result and url_result.links:
        for link in url_result.links:
            if link.is_brand_impersonation:
                brand_impersonation_count += 1
            elif link.is_mismatch:
                generic_mismatch_count += 1

            if link.is_raw_ip:
                raw_ip_count += 1
            if link.is_typosquat or link.is_homograph:
                url_typo_hom_count += 1
            if link.is_shortened:
                shortener_count += 1

    # 3.1 Brand Impersonation: +15 per link, capped at +30
    brand_imp_pts = min(30, brand_impersonation_count * 15)
    breakdown.append(ScoreBreakdownItem(
        category="URL Analysis",
        rule_name="Link Brand Impersonation",
        state=f"{brand_impersonation_count} links flagged",
        points_added=brand_imp_pts,
        formatted_line=f"Link Brand Impersonation: {brand_impersonation_count} links (+{brand_imp_pts})"
    ))

    # 3.2 Generic Domain Mismatch: +10 per link, capped at +20
    gen_mismatch_pts = min(20, generic_mismatch_count * 10)
    breakdown.append(ScoreBreakdownItem(
        category="URL Analysis",
        rule_name="Link Domain Mismatch",
        state=f"{generic_mismatch_count} links flagged",
        points_added=gen_mismatch_pts,
        formatted_line=f"Link Domain Mismatch: {generic_mismatch_count} links (+{gen_mismatch_pts})"
    ))

    # 3.3 Raw IP Link Destination: +10 per link, capped at +20
    raw_ip_pts = min(20, raw_ip_count * 10)
    breakdown.append(ScoreBreakdownItem(
        category="URL Analysis",
        rule_name="Raw IP Link Destination",
        state=f"{raw_ip_count} links flagged",
        points_added=raw_ip_pts,
        formatted_line=f"Raw IP Link Destination: {raw_ip_count} links (+{raw_ip_pts})"
    ))

    # 3.4 Destination Domain Typosquat / Homograph: +20 per link, capped at +20
    dest_typo_pts = min(20, url_typo_hom_count * 20)
    breakdown.append(ScoreBreakdownItem(
        category="URL Analysis",
        rule_name="Destination Typosquat/Homograph",
        state=f"{url_typo_hom_count} links flagged",
        points_added=dest_typo_pts,
        formatted_line=f"URL Destination Typosquat/Homograph: {url_typo_hom_count} links (+{dest_typo_pts})"
    ))

    # 3.5 URL Shorteners: +5 per link, capped at +10
    shortener_pts = min(10, shortener_count * 5)
    breakdown.append(ScoreBreakdownItem(
        category="URL Analysis",
        rule_name="URL Shortener Present",
        state=f"{shortener_count} links flagged",
        points_added=shortener_pts,
        formatted_line=f"URL Shortener Present: {shortener_count} links (+{shortener_pts})"
    ))

    # =========================================================================
    # 4. ATTACHMENT ANALYSIS LAYER SCORING
    # =========================================================================
    mismatch_count = 0
    dangerous_ext_count = 0
    double_ext_count = 0

    if attachment_result and attachment_result.attachments:
        for att_item in attachment_result.attachments:
            if att_item.is_signature_mismatch:
                mismatch_count += 1
            if att_item.is_dangerous_extension:
                dangerous_ext_count += 1
            if att_item.is_double_extension:
                double_ext_count += 1

    # 4.1 Signature Mismatch: +25 per attachment, capped at +30
    mismatch_pts = min(30, mismatch_count * 25)
    breakdown.append(ScoreBreakdownItem(
        category="Attachment Analysis",
        rule_name="Attachment Signature Mismatch",
        state=f"{mismatch_count} attachments flagged",
        points_added=mismatch_pts,
        formatted_line=f"Attachment Signature Mismatch: {mismatch_count} attachments (+{mismatch_pts})"
    ))

    # 4.2 Dangerous Extension: +20 per attachment, capped at +20
    dangerous_pts = min(20, dangerous_ext_count * 20)
    breakdown.append(ScoreBreakdownItem(
        category="Attachment Analysis",
        rule_name="Attachment Dangerous Extension",
        state=f"{dangerous_ext_count} attachments flagged",
        points_added=dangerous_pts,
        formatted_line=f"Attachment Dangerous Extension: {dangerous_ext_count} attachments (+{dangerous_pts})"
    ))

    # 4.3 Double Extension: +15 per attachment, capped at +15
    double_pts = min(15, double_ext_count * 15)
    breakdown.append(ScoreBreakdownItem(
        category="Attachment Analysis",
        rule_name="Attachment Double Extension",
        state=f"{double_ext_count} attachments flagged",
        points_added=double_pts,
        formatted_line=f"Attachment Double Extension: {double_ext_count} attachments (+{double_pts})"
    ))

    # =========================================================================
    # 5. HEADER INTEGRITY LAYER SCORING
    # =========================================================================
    if header_result:
        # Duplicate Headers: +15
        dup_pts = 15 if header_result.duplicate_headers else 0
        dup_state = f"{len(header_result.duplicate_headers)} headers duplicated ({', '.join(header_result.duplicate_headers)})" if header_result.duplicate_headers else "Clean"
        breakdown.append(ScoreBreakdownItem(
            category="Header Integrity",
            rule_name="Duplicate Critical Headers",
            state=dup_state,
            points_added=dup_pts,
            formatted_line=f"Duplicate Critical Headers: {dup_state} (+{dup_pts})"
        ))

        # Missing Message-ID or Date: +10
        missing_hdr_pts = 10 if (header_result.is_message_id_missing or header_result.is_date_missing or header_result.is_message_id_malformed) else 0
        missing_hdr_state = "Missing/Malformed" if missing_hdr_pts > 0 else "Present"
        breakdown.append(ScoreBreakdownItem(
            category="Header Integrity",
            rule_name="Message-ID & Date Integrity",
            state=missing_hdr_state,
            points_added=missing_hdr_pts,
            formatted_line=f"Message-ID & Date Integrity: {missing_hdr_state} (+{missing_hdr_pts})"
        ))

        # Date Header Sanity: +10 if future or implausible
        date_sanity_pts = 10 if (header_result.is_date_future or header_result.is_date_implausible) else 0
        date_sanity_state = "Future-dated" if header_result.is_date_future else ("Implausibly old (<1990)" if header_result.is_date_implausible else "Valid")
        breakdown.append(ScoreBreakdownItem(
            category="Header Integrity",
            rule_name="Date Header Sanity",
            state=date_sanity_state,
            points_added=date_sanity_pts,
            formatted_line=f"Date Header Sanity: {date_sanity_state} (+{date_sanity_pts})"
        ))

    # =========================================================================
    # 6. HTML CONTENT LAYER SCORING
    # =========================================================================
    if html_result:
        # Hidden Text / Invisible Links: +15
        hidden_pts = 15 if (html_result.has_hidden_text or html_result.has_invisible_links) else 0
        hidden_state = "Flagged" if hidden_pts > 0 else "Clean"
        breakdown.append(ScoreBreakdownItem(
            category="HTML Content",
            rule_name="Hidden Text & Invisible Links",
            state=hidden_state,
            points_added=hidden_pts,
            formatted_line=f"Hidden Text & Invisible Links: {hidden_state} (+{hidden_pts})"
        ))

        # JS Redirect: +15
        js_pts = 15 if html_result.has_js_redirect else 0
        js_state = "Flagged" if js_pts > 0 else "Clean"
        breakdown.append(ScoreBreakdownItem(
            category="HTML Content",
            rule_name="JavaScript Redirect Detection",
            state=js_state,
            points_added=js_pts,
            formatted_line=f"JavaScript Redirect: {js_state} (+{js_pts})"
        ))

        # Iframe Present: +5
        iframe_pts = 5 if html_result.has_iframe else 0
        iframe_state = "Present" if iframe_pts > 0 else "Clean"
        breakdown.append(ScoreBreakdownItem(
            category="HTML Content",
            rule_name="Iframe Detection",
            state=iframe_state,
            points_added=iframe_pts,
            formatted_line=f"Iframe Detection: {iframe_state} (+{iframe_pts})"
        ))

        # Large Base64 Payload: +10
        b64_pts = 10 if html_result.has_large_base64 else 0
        b64_state = "Large (>10KB)" if b64_pts > 0 else "Clean"
        breakdown.append(ScoreBreakdownItem(
            category="HTML Content",
            rule_name="Obfuscated Base64 Payload",
            state=b64_state,
            points_added=b64_pts,
            formatted_line=f"Base64 Payload: {b64_state} (+{b64_pts})"
        ))

    # =========================================================================
    # 7. CONTENT / SCAM KEYWORDS SCORING
    # =========================================================================
    if content_result:
        # +5 per category matched, capped at +20 total
        kw_pts = min(20, content_result.total_categories_count * 5)
        kw_state = f"{content_result.total_categories_count} categories matched ({content_result.total_matches_count} phrases)" if kw_pts > 0 else "0 matched"
        breakdown.append(ScoreBreakdownItem(
            category="Content Analysis",
            rule_name="Scam Indicator Keywords",
            state=kw_state,
            points_added=kw_pts,
            formatted_line=f"Scam Keywords: {kw_state} (+{kw_pts})"
        ))

    # =========================================================================
    # 8. DOMAIN AGE SCORING
    # =========================================================================
    if domain_age_result:
        age_pts = 0
        if domain_age_result.is_new_domain:
            age_pts = 15
        elif domain_age_result.status.startswith("Young Domain"):
            age_pts = 5

        breakdown.append(ScoreBreakdownItem(
            category="Domain Age",
            rule_name="Domain Registration Age",
            state=domain_age_result.status,
            points_added=age_pts,
            formatted_line=f"Domain Registration Age: {domain_age_result.status} (+{age_pts})"
        ))

    # =========================================================================
    # 9. LIVE REPUTATION INTELLIGENCE SCORING (VirusTotal & AbuseIPDB)
    # =========================================================================
    if reputation_result:
        # 9.1 VirusTotal URL Reputation Scoring
        vt = reputation_result.virustotal
        if vt and vt.is_configured:
            vt_pts = 0
            if vt.max_malicious_vendors >= 3:
                vt_pts = 25
            elif vt.max_malicious_vendors in (1, 2):
                vt_pts = 10

            vt_state = vt.status
            breakdown.append(ScoreBreakdownItem(
                category="Reputation Intelligence",
                rule_name="VirusTotal URL Reputation",
                state=vt_state,
                points_added=vt_pts,
                formatted_line=f"VirusTotal URL Reputation: {vt_state} (+{vt_pts})"
            ))

        # 9.2 AbuseIPDB Sending IP Reputation Scoring
        abuse = reputation_result.abuseipdb
        if abuse and abuse.is_configured:
            abuse_pts = 0
            score = abuse.abuse_confidence_score if abuse.abuse_confidence_score is not None else -1
            
            if score >= 75:
                abuse_pts = 20
            elif 25 <= score < 75:
                abuse_pts = 8
            elif score >= 0:
                abuse_pts = 0

            abuse_state = abuse.status
            breakdown.append(ScoreBreakdownItem(
                category="Reputation Intelligence",
                rule_name="AbuseIPDB IP Reputation",
                state=abuse_state,
                points_added=abuse_pts,
                formatted_line=f"AbuseIPDB IP Reputation: {abuse_state} (+{abuse_pts})"
            ))


    # =========================================================================
    # 4. HARD OVERRIDE RULE EVALUATION
    # =========================================================================
    # If SPF Fail AND DKIM Fail (both exact Fail, not SoftFail/Missing), force "Likely Spoofed"
    spf_failed = (spf_status == "Fail")
    dkim_failed = (dkim_status == "Fail")

    hard_flagged = False
    hard_flag_reason: Optional[str] = None

    if spf_failed and dkim_failed:
        hard_flagged = True
        hard_flag_reason = (
            f"Hard Override Triggered: Both SPF ({spf_status}) and DKIM ({dkim_status}) authentication failed. "
            "Verdict forced to Likely Spoofed."
        )

    # =========================================================================
    # 5. TOTAL SCORE & RISK BAND CALCULATION
    # =========================================================================
    raw_score = sum(item.points_added for item in breakdown)
    total_score = min(100, max(0, raw_score))

    if hard_flagged:
        risk_band = "Likely Spoofed"
        verdict_explanation = "CRITICAL: Email failed both SPF and DKIM authentication checks, indicating this email is likely spoofed."
    elif total_score >= 60:
        risk_band = "Likely Spoofed"
        verdict_explanation = "This email triggered critical forensic flags indicating domain spoofing, impersonation, or dangerous attachments."
    elif total_score >= 40:
        risk_band = "High Risk"
        verdict_explanation = "This email triggered multiple security flags, such as suspicious link mismatches, domain typosquatting, or authentication failures."
    elif total_score >= 15:
        risk_band = "Medium Risk"
        verdict_explanation = "This email passed key authentication checks but contains minor domain mismatches or standard ESP click-tracking infrastructure."
    elif total_score > 0:
        risk_band = "Low Risk"
        verdict_explanation = "This email shows minimal anomalies and passed primary authentication checks, making it safe for normal processing."
    else:
        risk_band = "Low Risk"
        verdict_explanation = "This email passed all authentication and domain checks without any suspicious links or attachments detected."

    return RiskScoreResult(
        total_score=total_score,
        raw_score=raw_score,
        risk_band=risk_band,
        hard_flagged=hard_flagged,
        hard_flag_reason=hard_flag_reason,
        verdict_explanation=verdict_explanation,
        breakdown=breakdown
    )

