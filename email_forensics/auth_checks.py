"""
email_forensics/auth_checks.py

Authentication check layer for Forenix Module 2 (Email Forensic Analysis).
Performs SPF (via pyspf), DKIM (via dkimpy), and DMARC (via checkdmarc / dnspython) checks.
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Union
from pathlib import Path
import re
import logging
import socket

# Import security/auth libraries with graceful fallback
try:
    import spf
except ImportError:
    spf = None

try:
    import dkim
except ImportError:
    dkim = None

try:
    import checkdmarc
except ImportError:
    checkdmarc = None

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

from .parser import ParsedEmail

logger = logging.getLogger(__name__)

# Regex for IPv4 and IPv6 extraction from Received headers
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b')


@dataclass
class SPFResult:
    """Stores SPF validation details."""
    status: str  # 'Pass', 'Fail', 'SoftFail', 'Neutral', 'None', 'TempError', 'PermError', or 'Unable to verify - [reason]'
    ip_used: Optional[str]
    domain_checked: Optional[str]
    raw_record: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DKIMResult:
    """Stores DKIM signature validation details."""
    status: str  # 'Pass', 'Fail', 'Missing', or 'Unable to verify - [reason]'
    domain_checked: Optional[str] = None
    selector: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DMARCResult:
    """Stores DMARC evaluation details."""
    status: str  # 'Pass', 'Fail', 'None', or 'Unable to verify - [reason]'
    domain_checked: Optional[str] = None
    policy: Optional[str] = None  # 'reject', 'quarantine', 'none', or None
    raw_record: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthResult:
    """Unified authentication result returned by run_auth_checks()."""
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    summary_status: str  # 'PASS', 'FAIL', 'SUSPICIOUS', 'INCOMPLETE'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'spf': self.spf.to_dict(),
            'dkim': self.dkim.to_dict(),
            'dmarc': self.dmarc.to_dict(),
            'summary_status': self.summary_status,
        }


def extract_topmost_received_ip(received_headers: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts sender IP from the topmost Received header (index 0 - hop closest to recipient).
    Returns tuple of (extracted_ip, hop_string_used).
    """
    if not received_headers:
        return None, None

    # Inspect topmost Received header (index 0)
    topmost_hop = received_headers[0]

    # Search for IPv4 first
    v4_matches = IPV4_REGEX.findall(topmost_hop)
    for ip in v4_matches:
        # Avoid loopback / invalid 0.0.0.0
        if not ip.startswith('127.') and ip != '0.0.0.0':
            return ip, topmost_hop

    # Search for IPv6
    v6_matches = IPV6_REGEX.findall(topmost_hop)
    for ip in v6_matches:
        if ip != '::1':
            return ip, topmost_hop

    # If no IP in index 0, fallback to second hop if available
    for hop in received_headers[1:]:
        v4_matches = IPV4_REGEX.findall(hop)
        for ip in v4_matches:
            if not ip.startswith('127.') and ip != '0.0.0.0':
                return ip, hop

    return None, topmost_hop


def extract_domain_from_email(email_addr: Optional[str]) -> Optional[str]:
    """Helper to extract domain part from an email address or header string."""
    if not email_addr or not isinstance(email_addr, str):
        return None
    email_clean = email_addr.strip()
    if '<' in email_clean and '>' in email_clean:
        email_clean = email_clean.split('<')[-1].split('>')[0]
    if '@' in email_clean:
        domain = email_clean.split('@')[-1].strip().lower()
        return domain if domain else None
    return None


def fetch_txt_records(domain: str) -> List[str]:
    """Fetches raw TXT records for a domain using dnspython."""
    if dns is None or not domain:
        return []
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5.0)
        records = []
        for rdata in answers:
            txt_content = "".join([b.decode('utf-8', errors='replace') for b in rdata.strings])
            records.append(txt_content)
        return records
    except Exception:
        return []


def check_spf(ip: Optional[str], from_domain: Optional[str], sender_address: Optional[str] = None) -> SPFResult:
    """
    Performs SPF validation using pyspf and dnspython.
    """
    if not from_domain:
        return SPFResult(
            status="Unable to verify - Missing From domain",
            ip_used=ip,
            domain_checked=None,
            details="Cannot perform SPF check without a valid From domain."
        )

    if not ip:
        return SPFResult(
            status="Unable to verify - Missing Received header IP",
            ip_used=None,
            domain_checked=from_domain,
            details="No connecting IP address could be extracted from Received headers."
        )

    raw_spf_record: Optional[str] = None
    txt_records = fetch_txt_records(from_domain)
    for txt in txt_records:
        if txt.startswith('v=spf1'):
            raw_spf_record = txt
            break

    if spf is None:
        return SPFResult(
            status="Unable to verify - pyspf library not installed",
            ip_used=ip,
            domain_checked=from_domain,
            raw_record=raw_spf_record,
            details="pyspf library is unavailable."
        )

    try:
        # Query SPF via pyspf
        sender_email = sender_address or f"postmaster@{from_domain}"
        spf_res_tuple = spf.check2(i=ip, s=sender_email, h=from_domain)
        
        if isinstance(spf_res_tuple, (tuple, list)):
            if len(spf_res_tuple) >= 3:
                result_code, explanation, _ = spf_res_tuple[:3]
            elif len(spf_res_tuple) == 2:
                result_code, explanation = spf_res_tuple
            else:
                result_code = spf_res_tuple[0]
                explanation = str(spf_res_tuple)
        else:
            result_code = str(spf_res_tuple)
            explanation = ""

        # Normalize result state
        code_map = {
            'pass': 'Pass',
            'fail': 'Fail',
            'softfail': 'SoftFail',
            'neutral': 'Neutral',
            'none': 'None',
            'temperror': 'TempError',
            'permerror': 'PermError'
        }
        status_str = code_map.get(str(result_code).lower(), f"Unable to verify - {result_code}")

        return SPFResult(
            status=status_str,
            ip_used=ip,
            domain_checked=from_domain,
            raw_record=raw_spf_record,
            details=f"pyspf code={result_code}, explanation={explanation}"
        )

    except socket.gaierror as e:
        return SPFResult(
            status="Unable to verify - DNS lookup failed",
            ip_used=ip,
            domain_checked=from_domain,
            raw_record=raw_spf_record,
            details=f"DNS resolution error: {e}"
        )
    except Exception as e:
        return SPFResult(
            status=f"Unable to verify - {type(e).__name__}",
            ip_used=ip,
            domain_checked=from_domain,
            raw_record=raw_spf_record,
            details=str(e)
        )


def check_dkim(raw_bytes: Optional[bytes]) -> DKIMResult:
    """
    Performs DKIM signature verification using dkimpy.
    """
    if not raw_bytes:
        return DKIMResult(
            status="Unable to verify - Missing raw message bytes",
            reason="DKIM check requires raw email message bytes."
        )

    if dkim is None:
        return DKIMResult(
            status="Unable to verify - dkimpy library not installed",
            reason="dkimpy library is unavailable."
        )

    # Check if DKIM-Signature header exists in message
    if b'dkim-signature:' not in raw_bytes.lower():
        return DKIMResult(
            status="Missing",
            reason="No DKIM-Signature header present in email."
        )

    # Extract signing domain and selector if possible
    domain_checked: Optional[str] = None
    selector: Optional[str] = None
    try:
        d_obj = dkim.DKIM(raw_bytes)
        sig_headers = d_obj.headers
        for name, val in sig_headers:
            if name.lower() == b'dkim-signature':
                val_str = val.decode('utf-8', errors='replace')
                d_match = re.search(r'\bd=([\w\.-]+)', val_str)
                s_match = re.search(r'\bs=([\w\.-]+)', val_str)
                if d_match:
                    domain_checked = d_match.group(1)
                if s_match:
                    selector = s_match.group(1)
                break
    except Exception as e:
        logger.debug(f"Could not parse DKIM header metadata: {e}")

    try:
        d_verify = dkim.DKIM(raw_bytes)
        is_valid = d_verify.verify()
        if is_valid:
            return DKIMResult(
                status="Pass",
                domain_checked=domain_checked,
                selector=selector
            )
        else:
            return DKIMResult(
                status="Fail",
                domain_checked=domain_checked,
                selector=selector,
                reason="DKIM signature verification failed (body or header hash mismatch)"
            )
    except dkim.ValidationError as e:
        return DKIMResult(
            status="Fail",
            domain_checked=domain_checked,
            selector=selector,
            reason=f"DKIM validation error: {e}"
        )
    except Exception as e:
        return DKIMResult(
            status=f"Unable to verify - {type(e).__name__}",
            domain_checked=domain_checked,
            selector=selector,
            reason=str(e)
        )


def check_dmarc(from_domain: Optional[str], spf_res: SPFResult, dkim_res: DKIMResult) -> DMARCResult:
    """
    Performs DMARC record lookup and evaluation using checkdmarc / dnspython.
    """
    if not from_domain:
        return DMARCResult(
            status="Unable to verify - Missing From domain",
            details="Cannot check DMARC without a valid From domain."
        )

    dmarc_domain = f"_dmarc.{from_domain}"
    raw_dmarc_record: Optional[str] = None
    policy: Optional[str] = None
    details_str: Optional[str] = None

    # Use checkdmarc library if available
    if checkdmarc:
        try:
            dmarc_res_dict = checkdmarc.check_dmarc(from_domain)
            raw_dmarc_record = dmarc_res_dict.get('record')
            tags = dmarc_res_dict.get('tags', {})
            if isinstance(tags, dict) and 'p' in tags:
                policy = tags['p'].get('value')
            elif raw_dmarc_record:
                p_match = re.search(r'\bp=(reject|quarantine|none)\b', raw_dmarc_record, re.IGNORECASE)
                if p_match:
                    policy = p_match.group(1).lower()

            details_str = f"checkdmarc valid={dmarc_res_dict.get('valid')}"
        except Exception as e:
            err_msg = str(e)
            if "DMARC record does not exist" in err_msg or "No DMARC record" in err_msg or "NXDOMAIN" in err_msg or "NoAnswer" in err_msg:
                return DMARCResult(
                    status="None",
                    domain_checked=from_domain,
                    policy=None,
                    raw_record=None,
                    details=f"No DMARC record found for {from_domain}"
                )
            details_str = f"checkdmarc exception: {e}"

    # Fallback DNS TXT query if record is still None
    if not raw_dmarc_record:
        txt_records = fetch_txt_records(dmarc_domain)
        for txt in txt_records:
            if txt.startswith('v=DMARC1'):
                raw_dmarc_record = txt
                p_match = re.search(r'\bp=(reject|quarantine|none)\b', txt, re.IGNORECASE)
                if p_match:
                    policy = p_match.group(1).lower()
                break

    if not raw_dmarc_record:
        # Check organizational domain if subdomain
        parts = from_domain.split('.')
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            org_txts = fetch_txt_records(f"_dmarc.{org_domain}")
            for txt in org_txts:
                if txt.startswith('v=DMARC1'):
                    raw_dmarc_record = txt
                    p_match = re.search(r'\bp=(reject|quarantine|none)\b', txt, re.IGNORECASE)
                    if p_match:
                        policy = p_match.group(1).lower()
                    break

    if not raw_dmarc_record:
        return DMARCResult(
            status="None",
            domain_checked=from_domain,
            policy=None,
            raw_record=None,
            details=f"No DMARC record found for {dmarc_domain}"
        )

    # Determine DMARC Pass/Fail based on SPF/DKIM alignment
    spf_aligned = (spf_res.status == 'Pass' and spf_res.domain_checked and spf_res.domain_checked.lower() == from_domain.lower())
    dkim_aligned = (dkim_res.status == 'Pass' and dkim_res.domain_checked and dkim_res.domain_checked.lower() == from_domain.lower())

    if spf_aligned or dkim_aligned:
        dmarc_status = "Pass"
    else:
        dmarc_status = "Fail"

    return DMARCResult(
        status=dmarc_status,
        domain_checked=from_domain,
        policy=policy,
        raw_record=raw_dmarc_record,
        details=f"DMARC policy={policy}, SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}"
    )



def run_auth_checks(parsed_email: ParsedEmail, raw_bytes: Optional[bytes] = None, file_path: Optional[Union[str, Path]] = None) -> AuthResult:
    """
    Combined orchestrator function taking a ParsedEmail and raw email bytes/file path.
    Runs SPF, DKIM, and DMARC validation and returns unified AuthResult.
    """
    # If raw_bytes not supplied directly, try reading from file_path
    if not raw_bytes and file_path:
        try:
            p = Path(file_path)
            if p.exists() and p.is_file():
                raw_bytes = p.read_bytes()
        except Exception as e:
            logger.warning(f"Could not read raw bytes for DKIM check from {file_path}: {e}")

    # Extract connecting sender IP from topmost Received header
    top_ip, _ = extract_topmost_received_ip(parsed_email.received_headers)

    # Extract From domain
    from_domain = extract_domain_from_email(parsed_email.from_address)
    if not from_domain and parsed_email.return_path:
        from_domain = extract_domain_from_email(parsed_email.return_path)

    # 1. SPF Check
    spf_res = check_spf(ip=top_ip, from_domain=from_domain, sender_address=parsed_email.from_address)

    # 2. DKIM Check
    dkim_res = check_dkim(raw_bytes=raw_bytes)

    # 3. DMARC Check
    dmarc_res = check_dmarc(from_domain=from_domain, spf_res=spf_res, dkim_res=dkim_res)

    # Overall Summary Status
    if spf_res.status == 'Pass' and dkim_res.status == 'Pass' and dmarc_res.status == 'Pass':
        summary_status = "PASS"
    elif spf_res.status in ('Fail', 'SoftFail') or dkim_res.status == 'Fail' or dmarc_res.status == 'Fail':
        summary_status = "FAIL"
    elif 'Unable to verify' in spf_res.status or 'Unable to verify' in dkim_res.status or 'Unable to verify' in dmarc_res.status:
        summary_status = "INCOMPLETE"
    else:
        summary_status = "SUSPICIOUS"

    return AuthResult(
        spf=spf_res,
        dkim=dkim_res,
        dmarc=dmarc_res,
        summary_status=summary_status
    )
