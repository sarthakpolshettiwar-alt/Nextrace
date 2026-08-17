"""
email_forensics/url_analysis.py

URL & Link Analysis Layer for Forenix Module 2 (Email Forensic Analysis).
Extracts links from HTML (<a href="">) and Plaintext email bodies, deduplicates links,
and detects domain mismatches, brand impersonation, raw IP targets, URL shorteners,
and typosquat/homograph destination domains.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Set
import re
import urllib.parse
import logging
from bs4 import BeautifulSoup

from .parser import ParsedEmail
from .domain_intel import (
    parse_domain_structure,
    detect_homograph,
    detect_typosquat,
    load_brand_domains,
    is_known_esp,
    DomainBreakdown
)

logger = logging.getLogger(__name__)

# List of known URL shorteners where target destination is obscured
KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "tiny.cc", "cutt.ly", "shorturl.at", "v.gd",
    "rebrand.ly", "bl.ink", "lnkd.in"
}

# Regex patterns for bare URL extraction and IPv4/IPv6 destination detection
BARE_URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
RAW_IP_URL_REGEX = re.compile(
    r'^(?:https?://)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?(?:/.*)?$',
    re.IGNORECASE
)
IPV4_ONLY_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')


@dataclass
class ExtractedLink:
    """Represents an extracted link and its forensic analysis flags."""
    link_text: str
    destination_url: str
    text_domain: Optional[str] = None
    destination_domain: Optional[str] = None
    is_mismatch: bool = False
    is_brand_impersonation: bool = False
    is_raw_ip: bool = False
    is_shortened: bool = False
    is_typosquat: bool = False
    is_homograph: bool = False
    is_esp_tracking: bool = False
    flags: List[str] = field(default_factory=list)
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:

        return asdict(self)


@dataclass
class UrlAnalysisResult:
    """Result container for URL & Link Analysis Layer."""
    status: str  # 'SUCCESS' or 'Unable to analyze - [reason]'
    links: List[ExtractedLink] = field(default_factory=list)
    total_links: int = 0
    suspicious_links_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'links': [l.to_dict() for l in self.links],
            'total_links': self.total_links,
            'suspicious_links_count': self.suspicious_links_count
        }


def normalize_url_destination(dest: str) -> str:
    """Normalizes destination URL for consistent analysis and deduplication (lowercased scheme/netloc, trimmed trailing slash)."""
    if not dest or not isinstance(dest, str):
        return ""
    clean = dest.strip()
    if not clean:
        return ""
    has_scheme = '://' in clean
    parsed = urllib.parse.urlparse(clean if has_scheme else f"http://{clean}")
    scheme = (parsed.scheme or 'http').lower()
    netloc = (parsed.netloc or '').lower()
    path = parsed.path
    if path == '/':
        path = ''
    elif path.endswith('/'):
        path = path.rstrip('/')

    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{scheme}://{netloc}{path}{query}{fragment}"


def normalize_link_text(link_text: str, dest_url: str) -> str:
    """Normalizes link text so minor variations of bare URL text map consistently."""
    if not link_text:
        return dest_url
    clean_txt = link_text.strip()
    if not clean_txt:
        return dest_url

    norm_dest = normalize_url_destination(dest_url)
    norm_txt_dest = normalize_url_destination(clean_txt)

    # If link text is just a representation of the destination URL (e.g. mail.nv-cta.com vs http://mail.nv-cta.com),
    # normalize link text to canonical destination URL.
    if norm_txt_dest and norm_dest and norm_txt_dest.lower() == norm_dest.lower():
        return norm_dest

    clean_dest = dest_url.strip().rstrip('/')
    if clean_txt.lower() == clean_dest.lower() or clean_txt.lower() == (clean_dest.lower() + '/'):
        return clean_dest
    return clean_txt


def extract_links_from_html(body_html: str) -> List[Tuple[str, str]]:
    """Extracts (link_text, href_destination) pairs from HTML <a> tags using BeautifulSoup."""
    if not body_html or not isinstance(body_html, str):
        return []

    extracted: List[Tuple[str, str]] = []
    try:
        soup = BeautifulSoup(body_html, 'html.parser')
        for a_tag in soup.find_all('a'):
            href = a_tag.get('href')
            if not href or not isinstance(href, str):
                continue
            
            href_clean = href.strip()

            # Filter out non-HTTP(S) schemes like mailto:, tel:, javascript:, anchors
            if href_clean.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                continue

            link_text = a_tag.get_text(strip=True) or href_clean
            extracted.append((link_text, href_clean))
    except Exception as e:
        logger.warning(f"Error parsing HTML body for links: {e}")

    return extracted


def extract_links_from_plaintext(body_plain: str) -> List[Tuple[str, str]]:
    """Extracts bare URLs from Plaintext email body using regex pattern."""
    if not body_plain or not isinstance(body_plain, str):
        return []

    extracted: List[Tuple[str, str]] = []
    matches = BARE_URL_REGEX.findall(body_plain)
    for url in matches:
        clean_url = url.rstrip('.,);:\'">')
        if clean_url:
            extracted.append((clean_url, clean_url))

    return extracted


def is_url_shortener(domain_or_url: str) -> bool:
    """Checks if a domain or URL belongs to a known URL shortener service."""
    if not domain_or_url:
        return False
    
    clean = domain_or_url.strip().lower()
    if clean in KNOWN_URL_SHORTENERS:
        return True

    # Parse host if URL passed
    parsed = urllib.parse.urlparse(clean if '://' in clean else f"http://{clean}")
    host = (parsed.netloc or parsed.path).split(':')[0]
    return host in KNOWN_URL_SHORTENERS


def analyze_single_link(link_text: str, destination_url: str, brand_list: List[str]) -> ExtractedLink:
    """Analyzes a single link for domain mismatch, brand impersonation, raw IP, shortener, and typosquat/homograph flags."""
    flags: List[str] = []
    is_mismatch = False
    is_brand_impersonate = False
    is_raw_ip = False
    is_shortened = False
    is_typosquat = False
    is_homograph = False

    text_domain: Optional[str] = None
    destination_domain: Optional[str] = None

    # Safe display truncation for logging details
    disp_text = (link_text[:60] + '...') if len(link_text) > 63 else link_text
    disp_dest = (destination_url[:60] + '...') if len(destination_url) > 63 else destination_url

    # 1. Raw IP Check
    parsed_dest = urllib.parse.urlparse(destination_url if '://' in destination_url else f"http://{destination_url}")
    host_dest = (parsed_dest.netloc or parsed_dest.path).split(':')[0]

    if IPV4_ONLY_REGEX.match(host_dest) or RAW_IP_URL_REGEX.match(destination_url):
        is_raw_ip = True
        flags.append("Link destination is a raw IP address instead of a domain")
    else:
        # Parse destination domain using domain_intel tldextract parsing
        dest_breakdown = parse_domain_structure(host_dest or destination_url)
        if dest_breakdown and dest_breakdown.registered_domain:
            destination_domain = dest_breakdown.registered_domain

    # 2. URL Shortener Check
    if is_url_shortener(host_dest) or is_url_shortener(destination_domain or ""):
        is_shortened = True
        flags.append("Shortened URL detected, destination obscured (redirects not followed for safety)")

    # Check if destination domain is a known ESP click-tracking domain
    esp_domain_target = destination_domain or host_dest
    is_esp = is_known_esp(esp_domain_target)
    is_esp_tracking = is_esp

    # 3. Visible Text Domain vs Destination Domain Mismatch Check
    text_breakdown = parse_domain_structure(link_text)
    if text_breakdown and text_breakdown.registered_domain:
        text_domain = text_breakdown.registered_domain
        if destination_domain and text_domain.lower() != destination_domain.lower():
            if is_esp:
                flags.append(f"Link routed through known ESP tracking domain ({esp_domain_target}) — this is standard corporate email click-tracking, not inherently suspicious")
            else:
                is_mismatch = True
                flags.append(f"Link text domain mismatch: visible text claims '{text_domain}', but destination goes to '{destination_domain}'")

    # 4. Brand Impersonation Check in Visible Link Text
    if not is_mismatch and brand_list:
        clean_text_lower = link_text.lower()
        for brand in brand_list:
            # Check if text mentions brand (e.g. "PayPal", "Microsoft")
            if brand in clean_text_lower:
                # If destination domain exists and does not contain/match the brand
                if destination_domain:
                    dest_lower = destination_domain.lower()
                    if brand not in dest_lower:
                        if is_esp:
                            if not any("known ESP tracking domain" in f for f in flags):
                                flags.append(f"Link routed through known ESP tracking domain ({esp_domain_target}) — this is standard corporate email click-tracking, not inherently suspicious")
                        else:
                            is_brand_impersonate = True
                            flags.append(f"Brand impersonation mismatch: visible text mentions brand '{brand}', but destination domain is '{destination_domain}'")
                            break

    # 5. Destination Domain Typosquatting & Homograph Checks
    if destination_domain and not is_raw_ip and not is_shortened:
        dest_bd = parse_domain_structure(destination_domain)
        if dest_bd and dest_bd.domain:
            # Homograph / Punycode check on destination
            is_hom, hom_details = detect_homograph(dest_bd.raw_domain)
            if is_hom:
                is_homograph = True
                flags.append(f"Destination domain is a Punycode/homograph: {hom_details}")

            # Typosquat check on destination domain label
            is_typ, matched_brand, dist, typ_details = detect_typosquat(dest_bd.domain, brand_list)
            if is_typ:
                is_typosquat = True
                flags.append(f"Destination domain is a typosquat of brand '{matched_brand}' (distance {dist})")


    details_str = "; ".join(flags) if flags else "Link is clean (text and destination domain align)"

    return ExtractedLink(
        link_text=link_text,
        destination_url=destination_url,
        text_domain=text_domain,
        destination_domain=destination_domain,
        is_mismatch=is_mismatch,
        is_brand_impersonation=is_brand_impersonate,
        is_raw_ip=is_raw_ip,
        is_shortened=is_shortened,
        is_typosquat=is_typosquat,
        is_homograph=is_homograph,
        is_esp_tracking=is_esp_tracking,
        flags=flags,
        details=details_str
    )



def run_url_analysis(parsed_email: ParsedEmail) -> UrlAnalysisResult:
    """
    Main entry point for URL & Link Analysis Layer.
    Extracts links from HTML and Plaintext bodies, deduplicates them with normalized keys, and analyzes each link.
    """
    raw_links: List[Tuple[str, str]] = []

    # 1. Extract from HTML body
    if parsed_email.body_html:
        raw_links.extend(extract_links_from_html(parsed_email.body_html))

    # 2. Extract from Plaintext body
    if parsed_email.body_plain:
        raw_links.extend(extract_links_from_plaintext(parsed_email.body_plain))

    if not raw_links:
        return UrlAnalysisResult(
            status="SUCCESS",
            links=[],
            total_links=0,
            suspicious_links_count=0
        )

    # 3. Deduplicate links while preserving order using normalized keys
    seen_keys: Set[Tuple[str, str]] = set()
    deduped_links: List[Tuple[str, str]] = []
    for txt, dest in raw_links:
        norm_dest = normalize_url_destination(dest)
        norm_txt = normalize_link_text(txt, norm_dest)
        key = (norm_txt.strip().lower(), norm_dest.strip().lower())
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_links.append((norm_txt.strip(), norm_dest.strip()))

    # Load brand list for brand impersonation and typosquat checks
    brand_list = load_brand_domains()

    # 4. Analyze each extracted link
    analyzed_links: List[ExtractedLink] = []
    suspicious_count = 0

    for txt, dest in deduped_links:
        analyzed = analyze_single_link(txt, dest, brand_list)
        if (analyzed.is_mismatch or analyzed.is_brand_impersonation or 
            analyzed.is_raw_ip or analyzed.is_shortened or 
            analyzed.is_typosquat or analyzed.is_homograph):
            suspicious_count += 1
        analyzed_links.append(analyzed)


    return UrlAnalysisResult(
        status="SUCCESS",
        links=analyzed_links,
        total_links=len(analyzed_links),
        suspicious_links_count=suspicious_count
    )
