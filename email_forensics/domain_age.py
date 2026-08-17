"""
email_forensics/domain_age.py

Domain Age Check for Forenix Module 2.
Performs WHOIS domain lookup to determine sender domain registration age:
- Age < 90 days: Elevated risk flag
- Age 90 - 365 days: Informational note
- WHOIS failure / privacy shield / timeout: "Unable to determine domain age"
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union, List
import logging
import tldextract
from .parser import ParsedEmail

try:
    import whois
except ImportError:
    whois = None

logger = logging.getLogger(__name__)


@dataclass
class DomainAgeResult:
    """Stores findings from Domain Age Check."""
    domain_checked: Optional[str] = None
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    status: str = "Unable to determine domain age"  # 'New Domain (<90 days)', 'Young Domain (90-365 days)', 'Established Domain (>365 days)', or 'Unable to determine domain age'
    is_new_domain: bool = False
    details: str = "WHOIS lookup pending or unavailable"
    findings: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_registered_domain(email_addr: Optional[str]) -> Optional[str]:
    """Helper to extract registered domain from email address."""
    if not email_addr or '@' not in email_addr:
        return None
    domain_part = email_addr.split('@', 1)[1].strip()
    extracted = tldextract.extract(domain_part)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return domain_part.lower()


def run_domain_age_check(parsed_email: ParsedEmail, now: Optional[datetime] = None) -> DomainAgeResult:
    """
    Looks up WHOIS creation date for sender domain and calculates registration age.

    :param parsed_email: ParsedEmail instance.
    :param now: Current UTC timestamp.
    :return: DomainAgeResult object.
    """
    result = DomainAgeResult()
    
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    sender_domain = _extract_registered_domain(parsed_email.from_address)
    if not sender_domain:
        result.status = "Unable to determine domain age - Missing sender domain"
        result.details = "No valid sender email address or domain found in From header."
        return result

    result.domain_checked = sender_domain

    if whois is None:
        result.status = "Unable to determine domain age - WHOIS module not installed"
        result.details = "python-whois library is not available in environment."
        return result

    try:
        w = whois.whois(sender_domain)
        creation_date_raw = getattr(w, 'creation_date', None)

        if not creation_date_raw:
            result.status = "Unable to determine domain age - WHOIS date missing"
            result.details = f"WHOIS query for '{sender_domain}' returned no creation date (privacy protection or missing record)."
            return result

        # WHOIS library can return datetime, string, or list of datetimes
        creation_dt: Optional[datetime] = None
        if isinstance(creation_date_raw, list):
            creation_date_raw = creation_date_raw[0]

        if isinstance(creation_date_raw, datetime):
            creation_dt = creation_date_raw
        elif isinstance(creation_date_raw, str):
            try:
                from dateutil import parser as dateutil_parser
                creation_dt = dateutil_parser.parse(creation_date_raw)
            except Exception:
                pass

        if not creation_dt:
            result.status = "Unable to determine domain age - Unparseable creation date"
            result.details = f"Unparseable WHOIS creation date: {creation_date_raw}"
            return result

        if creation_dt.tzinfo is None:
            creation_dt = creation_dt.replace(tzinfo=timezone.utc)

        result.creation_date = creation_dt.strftime("%Y-%m-%d")
        age_days = (now - creation_dt).days
        result.age_days = max(0, age_days)

        if age_days < 90:
            result.status = "New Domain (<90 days)"
            result.is_new_domain = True
            result.details = f"Domain '{sender_domain}' was created on {result.creation_date} ({age_days} days ago). Elevated risk for phishing."
            result.findings.append({
                'rule': 'New Domain Registration (<90 days)',
                'severity': 'HIGH',
                'evidence': result.details
            })
        elif 90 <= age_days <= 365:
            result.status = "Young Domain (90-365 days)"
            result.details = f"Domain '{sender_domain}' was created on {result.creation_date} ({age_days} days ago)."
            result.findings.append({
                'rule': 'Young Domain Registration (90-365 days)',
                'severity': 'LOW',
                'evidence': result.details
            })
        else:
            result.status = "Established Domain (>365 days)"
            result.details = f"Domain '{sender_domain}' was created on {result.creation_date} ({age_days} days ago)."

    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {sender_domain}: {e}")
        result.status = "Unable to determine domain age - Lookup failed"
        result.details = f"WHOIS query for '{sender_domain}' failed or timed out: {e}"

    return result
