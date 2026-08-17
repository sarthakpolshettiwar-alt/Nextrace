"""
email_forensics/header_integrity.py

Header Integrity Analysis for Forenix Module 2.
Performs deterministic, offline checks on email headers:
- Message-ID format validation & missing/malformed check
- Duplicate header detection (header injection / spoofing indicator)
- Missing critical headers check (From, Date, Message-ID)
- Date header sanity check (future-dated or implausibly old)
- X-Originating-IP extraction (informational)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import re
import logging
from .parser import ParsedEmail

logger = logging.getLogger(__name__)

# Single-occurrence critical headers that shouldn't be duplicated
SINGLE_OCCURRENCE_HEADERS = {"from", "subject", "date", "message-id", "to", "reply-to", "return-path"}
MESSAGE_ID_REGEX = re.compile(r'^<.+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$|^[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


@dataclass
class HeaderIntegrityResult:
    """Stores findings from Header Integrity Analysis."""
    is_message_id_missing: bool = False
    is_message_id_malformed: bool = False
    message_id_evidence: Optional[str] = None
    
    duplicate_headers: List[str] = field(default_factory=list)
    duplicate_headers_evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    missing_critical_headers: List[str] = field(default_factory=list)
    
    is_date_missing: bool = False
    is_date_future: bool = False
    is_date_implausible: bool = False
    date_evidence: Optional[str] = None
    
    x_originating_ip: Optional[str] = None
    
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_header_integrity_check(parsed_email: ParsedEmail, now: Optional[datetime] = None) -> HeaderIntegrityResult:
    """
    Evaluates header integrity rules against a parsed email.

    :param parsed_email: ParsedEmail unified instance.
    :param now: Current UTC timestamp (defaults to datetime.now(timezone.utc)).
    :return: HeaderIntegrityResult object.
    """
    result = HeaderIntegrityResult()
    findings = []

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # 1. Message-ID Validation
    msg_id = parsed_email.message_id
    if not msg_id or not msg_id.strip():
        result.is_message_id_missing = True
        result.message_id_evidence = "Message-ID header is missing entirely."
        findings.append({
            'rule': 'Missing Message-ID',
            'severity': 'HIGH',
            'evidence': result.message_id_evidence
        })
    else:
        msg_id_clean = msg_id.strip()
        result.message_id_evidence = msg_id_clean
        # Format check: must contain '@' and domain-like structure
        if '@' not in msg_id_clean or len(msg_id_clean) < 5 or not MESSAGE_ID_REGEX.match(msg_id_clean):
            # Soft fallback: at minimum require '@' with characters before and after
            at_idx = msg_id_clean.find('@')
            if at_idx <= 0 or at_idx >= len(msg_id_clean) - 1:
                result.is_message_id_malformed = True
                findings.append({
                    'rule': 'Malformed Message-ID',
                    'severity': 'HIGH',
                    'evidence': f"Message-ID header format is invalid: '{msg_id_clean}'"
                })

    # 2. Duplicate Header Detection
    header_counts: Dict[str, List[str]] = {}
    if parsed_email.all_headers:
        for hdr in parsed_email.all_headers:
            name = str(hdr.get('name', '')).strip().lower()
            val = str(hdr.get('value', '')).strip()
            if name in SINGLE_OCCURRENCE_HEADERS:
                header_counts.setdefault(name, []).append(val)

    for h_name, val_list in header_counts.items():
        if len(val_list) > 1:
            canonical_name = h_name.title() if h_name != 'message-id' else 'Message-ID'
            result.duplicate_headers.append(canonical_name)
            result.duplicate_headers_evidence.append({
                'header': canonical_name,
                'count': len(val_list),
                'values': val_list
            })
            findings.append({
                'rule': 'Duplicate Critical Header',
                'severity': 'HIGH',
                'evidence': f"Header '{canonical_name}' appears {len(val_list)} times: {val_list}"
            })

    # 3. Missing Critical Headers Check (From, Date, Message-ID)
    if not parsed_email.from_address and not parsed_email.from_name:
        result.missing_critical_headers.append('From')
        findings.append({
            'rule': 'Missing Critical Header',
            'severity': 'HIGH',
            'evidence': "Header 'From' is absent."
        })

    if not parsed_email.date:
        result.is_date_missing = True
        result.missing_critical_headers.append('Date')
        findings.append({
            'rule': 'Missing Critical Header',
            'severity': 'HIGH',
            'evidence': "Header 'Date' is absent."
        })

    if result.is_message_id_missing and 'Message-ID' not in result.missing_critical_headers:
        result.missing_critical_headers.append('Message-ID')

    # 4. Date Header Sanity Check
    email_dt = parsed_email.date
    if isinstance(email_dt, str):
        from .parser import _parse_datetime_str
        email_dt = _parse_datetime_str(email_dt)

    if isinstance(email_dt, datetime):
        if email_dt.tzinfo is None:
            email_dt = email_dt.replace(tzinfo=timezone.utc)

        result.date_evidence = email_dt.isoformat()


        # Future-dated check (> 1 hour ahead)
        if email_dt > now + timedelta(hours=1):
            result.is_date_future = True
            findings.append({
                'rule': 'Future-Dated Email',
                'severity': 'MEDIUM',
                'evidence': f"Date header '{email_dt.isoformat()}' is in the future relative to analysis time '{now.isoformat()}'"
            })

        # Implausible old check (< Year 1990)
        if email_dt.year < 1990:
            result.is_date_implausible = True
            findings.append({
                'rule': 'Implausibly Old Date',
                'severity': 'HIGH',
                'evidence': f"Date header '{email_dt.isoformat()}' is before 1990 (possible epoch artifact or forgery)"
            })

    # 5. X-Originating-IP Extraction (Informational)
    if parsed_email.all_headers:
        for hdr in parsed_email.all_headers:
            if str(hdr.get('name', '')).strip().lower() == 'x-originating-ip':
                raw_ip_val = str(hdr.get('value', '')).strip()
                # Clean brackets e.g. [1.2.3.4]
                ip_clean = re.sub(r'[\[\]\s]', '', raw_ip_val)
                result.x_originating_ip = ip_clean
                break

    result.findings = findings
    return result
