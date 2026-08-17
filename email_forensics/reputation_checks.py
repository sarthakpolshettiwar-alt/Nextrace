"""
email_forensics/reputation_checks.py

Live Reputation Intelligence (Beta) for Forenix Module 2.
Performs third-party API queries against VirusTotal and AbuseIPDB:
- VirusTotal API v3: Scans extracted URLs (capped at max 5 unique URLs to respect rate limits)
- AbuseIPDB API v2: Checks sending IP reputation (with 24-hour local caching to preserve quota)

Graceful Fail-Safe Design:
- Missing API keys -> Returns "Reputation check not configured"
- API timeout / network error -> Returns "Unable to verify — [reason]"
- NEVER raises exceptions or blocks the core offline analysis pipeline.
"""

import os
import base64
import time
import logging
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional
import requests
import tldextract

logger = logging.getLogger(__name__)

# VirusTotal & AbuseIPDB Endpoints
VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
ABUSEIPDB_CHECK_API = "https://api.abuseipdb.com/api/v2/check"

# Caching & Rate Limits
MAX_VT_URLS_CHECKED = 5
ABUSEIPDB_CACHE_TTL_SECONDS = 86400  # 24 hours

# Simple in-memory cache for AbuseIPDB IP lookups: { ip_str: (timestamp, result_dict) }
_IP_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}


@dataclass
class VirusTotalURLItem:
    url: str
    domain: str
    status: str  # e.g., '3/89 vendors flagged', '0/89 vendors flagged', 'Not previously scanned by VirusTotal'
    malicious_count: int = 0
    suspicious_count: int = 0
    total_vendors: int = 0
    is_scanned: bool = False
    raw_details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VirusTotalResult:
    is_configured: bool = False
    status: str = "Reputation check not configured"
    urls_checked: List[VirusTotalURLItem] = field(default_factory=list)
    total_urls_found: int = 0
    checked_count: int = 0
    flagged_urls_count: int = 0
    max_malicious_vendors: int = 0
    disclosure_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_configured': self.is_configured,
            'status': self.status,
            'total_urls_found': self.total_urls_found,
            'checked_count': self.checked_count,
            'flagged_urls_count': self.flagged_urls_count,
            'max_malicious_vendors': self.max_malicious_vendors,
            'disclosure_note': self.disclosure_note,
            'urls_checked': [u.to_dict() for u in self.urls_checked]
        }


@dataclass
class AbuseIPDBResult:
    is_configured: bool = False
    status: str = "Reputation check not configured"
    ip_checked: Optional[str] = None
    abuse_confidence_score: Optional[int] = None  # 0 - 100
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    total_reports: Optional[int] = None
    is_whitelisted: Optional[bool] = None
    raw_details: str = ""
    is_cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReputationCheckResult:
    virustotal: VirusTotalResult = field(default_factory=VirusTotalResult)
    abuseipdb: AbuseIPDBResult = field(default_factory=AbuseIPDBResult)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'virustotal': self.virustotal.to_dict(),
            'abuseipdb': self.abuseipdb.to_dict()
        }


def _encode_url_id(url: str) -> str:
    """Helper to encode URL into VirusTotal API v3 URL identifier format."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def _check_single_url_virustotal(url: str, api_key: str, timeout: int = 5) -> VirusTotalURLItem:
    """Queries VirusTotal API v3 for a single URL's scan report."""
    item = VirusTotalURLItem(url=url, domain="", status="Unable to verify")
    
    # Extract domain for display
    extracted = tldextract.extract(url)
    item.domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain else url

    url_id = _encode_url_id(url)
    endpoint = f"{VIRUSTOTAL_URL_API}/{url_id}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            item.malicious_count = malicious
            item.suspicious_count = suspicious
            item.total_vendors = total
            item.is_scanned = True
            
            if total > 0:
                item.status = f"{malicious + suspicious}/{total} vendors flagged"
            else:
                item.status = "0 vendors flagged"
            
            item.raw_details = f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}"
        elif resp.status_code == 404:
            item.status = "Not previously scanned by VirusTotal"
            item.is_scanned = False
            item.raw_details = "URL has no prior scan record on VirusTotal."
        elif resp.status_code == 429:
            item.status = "Unable to verify — VirusTotal API rate limit hit"
            item.raw_details = "HTTP 429 Rate limit exceeded."
        else:
            item.status = f"Unable to verify — HTTP {resp.status_code}"
            item.raw_details = f"VirusTotal response: {resp.status_code} {resp.text[:100]}"
    except requests.Timeout:
        item.status = "Unable to verify — Request timed out"
        item.raw_details = "VirusTotal API call timed out (5s)."
    except Exception as e:
        logger.warning(f"VirusTotal query error for {url}: {e}")
        item.status = f"Unable to verify — {str(e)}"
        item.raw_details = str(e)

    return item


def run_virustotal_checks(urls: List[str], timeout: int = 5) -> VirusTotalResult:
    """
    Executes VirusTotal reputation checks for extracted email URLs.
    Caps URL inspections at MAX_VT_URLS_CHECKED (5) to respect API rate limits.
    """
    vt_result = VirusTotalResult()
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    if not vt_key:
        vt_result.is_configured = False
        vt_result.status = "Reputation check not configured"
        vt_result.disclosure_note = "VIRUSTOTAL_API_KEY is not set in environment."
        return vt_result

    vt_result.is_configured = True
    vt_result.total_urls_found = len(urls)

    if not urls:
        vt_result.status = "No URLs found in email to check"
        vt_result.disclosure_note = "No extracted URLs present for reputation verification."
        return vt_result

    # Deduplicate URLs while preserving order
    unique_urls = []
    seen = set()
    for u in urls:
        if u not in seen and u.startswith(("http://", "https://")):
            seen.add(u)
            unique_urls.append(u)

    urls_to_check = unique_urls[:MAX_VT_URLS_CHECKED]
    vt_result.checked_count = len(urls_to_check)
    vt_result.disclosure_note = f"Checked {vt_result.checked_count} of {vt_result.total_urls_found} URLs against VirusTotal due to API rate limits."

    flagged = 0
    max_malicious = 0

    for u in urls_to_check:
        item = _check_single_url_virustotal(u, vt_key, timeout=timeout)
        vt_result.urls_checked.append(item)
        
        total_flagged = item.malicious_count + item.suspicious_count
        if total_flagged > 0:
            flagged += 1
            if total_flagged > max_malicious:
                max_malicious = total_flagged

    vt_result.flagged_urls_count = flagged
    vt_result.max_malicious_vendors = max_malicious
    vt_result.status = f"Completed — {flagged} of {vt_result.checked_count} URLs flagged by security vendors"

    return vt_result


def run_abuseipdb_check(ip_address: Optional[str], timeout: int = 5) -> AbuseIPDBResult:
    """
    Queries AbuseIPDB API v2 for sending IP address reputation score.
    Uses 24-hour local caching keyed by IP address to preserve API quota.
    """
    abuse_result = AbuseIPDBResult()
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        abuse_result.is_configured = False
        abuse_result.status = "Reputation check not configured"
        abuse_result.raw_details = "ABUSEIPDB_API_KEY is not set in environment."
        return abuse_result

    abuse_result.is_configured = True

    if not ip_address:
        abuse_result.status = "No valid sending IP extracted"
        abuse_result.raw_details = "No originating IP address was available in email headers."
        return abuse_result

    abuse_result.ip_checked = ip_address

    # Check 24-hr TTL local cache
    now_time = time.time()
    if ip_address in _IP_CACHE:
        cache_time, cached_data = _IP_CACHE[ip_address]
        if now_time - cache_time < ABUSEIPDB_CACHE_TTL_SECONDS:
            logger.info(f"AbuseIPDB cache hit for IP {ip_address}")
            return AbuseIPDBResult(
                is_configured=True,
                status=cached_data.get('status', 'Completed'),
                ip_checked=ip_address,
                abuse_confidence_score=cached_data.get('abuseConfidenceScore'),
                country_code=cached_data.get('countryCode'),
                isp=cached_data.get('isp'),
                domain=cached_data.get('domain'),
                total_reports=cached_data.get('totalReports'),
                is_whitelisted=cached_data.get('isWhitelisted'),
                raw_details=f"Retrieved from local cache (TTL 24h). {cached_data.get('raw_details', '')}",
                is_cached=True
            )

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

    try:
        resp = requests.get(ABUSEIPDB_CHECK_API, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode")
            isp = data.get("isp")
            dom = data.get("domain")
            reports = data.get("totalReports", 0)
            whitelisted = data.get("isWhitelisted", False)

            abuse_result.status = f"Abuse Confidence Score: {score}% ({reports} reports)"
            abuse_result.abuse_confidence_score = score
            abuse_result.country_code = country
            abuse_result.isp = isp
            abuse_result.domain = dom
            abuse_result.total_reports = reports
            abuse_result.is_whitelisted = whitelisted
            abuse_result.raw_details = f"IP: {ip_address}, Score: {score}%, Country: {country}, ISP: {isp}, Reports: {reports}"

            # Store in cache
            _IP_CACHE[ip_address] = (now_time, {
                'status': abuse_result.status,
                'abuseConfidenceScore': score,
                'countryCode': country,
                'isp': isp,
                'domain': dom,
                'totalReports': reports,
                'isWhitelisted': whitelisted,
                'raw_details': abuse_result.raw_details
            })
        elif resp.status_code == 429:
            abuse_result.status = "Unable to verify — AbuseIPDB API rate limit hit"
            abuse_result.raw_details = "HTTP 429 Daily quota reached."
        else:
            abuse_result.status = f"Unable to verify — HTTP {resp.status_code}"
            abuse_result.raw_details = f"AbuseIPDB response: {resp.status_code} {resp.text[:100]}"
    except requests.Timeout:
        abuse_result.status = "Unable to verify — Request timed out"
        abuse_result.raw_details = "AbuseIPDB API call timed out (5s)."
    except Exception as e:
        logger.warning(f"AbuseIPDB query error for IP {ip_address}: {e}")
        abuse_result.status = f"Unable to verify — {str(e)}"
        abuse_result.raw_details = str(e)

    return abuse_result


def run_reputation_checks(parsed_email, url_result=None, auth_result=None, timeout: int = 5) -> ReputationCheckResult:
    """
    Orchestrates live VirusTotal and AbuseIPDB reputation checks.
    Guaranteed fail-safe execution — wrapped entirely in try/except blocks.
    """
    result = ReputationCheckResult()

    try:
        # Extract URLs
        extracted_urls = []
        if url_result and getattr(url_result, 'links', None):
            for link in url_result.links:
                dest = getattr(link, 'destination_url', None) or getattr(link, 'url', None)
                if dest:
                    extracted_urls.append(dest)

        result.virustotal = run_virustotal_checks(extracted_urls, timeout=timeout)
    except Exception as e:
        logger.error(f"Error during VirusTotal execution: {e}", exc_info=True)
        result.virustotal.status = f"Unable to verify — {str(e)}"

    try:
        # Extract Sending IP from auth_result or received headers
        sending_ip = None
        if auth_result and getattr(auth_result, 'spf', None) and getattr(auth_result.spf, 'ip_used', None):
            sending_ip = auth_result.spf.ip_used

        if not sending_ip and getattr(parsed_email, 'all_headers', None):
            for hdr in parsed_email.all_headers:
                if hdr.get('name', '').lower() == 'x-originating-ip':
                    sending_ip = hdr.get('value', '').strip('[] ')
                    break

        result.abuseipdb = run_abuseipdb_check(sending_ip, timeout=timeout)
    except Exception as e:
        logger.error(f"Error during AbuseIPDB execution: {e}", exc_info=True)
        result.abuseipdb.status = f"Unable to verify — {str(e)}"

    return result
