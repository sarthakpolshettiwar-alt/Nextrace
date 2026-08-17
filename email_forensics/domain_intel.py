"""
email_forensics/domain_intel.py

Domain Intelligence Layer for Forenix Module 2 (Email Forensic Analysis).
Provides accurate domain parsing via tldextract, Homograph/Punycode & mixed-script detection via idna & unicodedata,
and typosquatting detection via rapidfuzz against a curated brand list.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
import json
import logging
import unicodedata
import idna

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    from rapidfuzz.distance import Levenshtein
except ImportError:
    Levenshtein = None

from .parser import ParsedEmail

logger = logging.getLogger(__name__)

# Path to curated brand domains & ESP domains files
BRAND_DOMAINS_FILE = Path(__file__).parent / "brand_domains.json"
KNOWN_ESP_FILE = Path(__file__).parent / "known_esp_providers.json"


def load_known_esp_domains() -> List[str]:
    """
    Loads curated list of known Email Service Provider (ESP) domains from known_esp_providers.json.
    Checked against N known ESP infrastructure domains.
    """
    if KNOWN_ESP_FILE.exists():
        try:
            with open(KNOWN_ESP_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                esps = data.get('known_esp_domains', [])
                return [e.lower() for e in esps]
        except Exception as e:
            logger.warning(f"Error reading known_esp_providers.json: {e}")

    # Fallback inline ESP list
    return [
        "amazonses.com", "awstrack.me", "sendgrid.net", "sendgrid.com", "mailchimp.com",
        "mandrillapp.com", "sparkpostmail.com", "constantcontact.com", "hubspot.com",
        "list-manage.com", "salesforce.com", "marketo.com", "mailgun.org", "mailgun.net",
        "customeriomail.com", "mktomail.com", "postmarkapp.com", "ctctsent.com"
    ]


def is_known_esp(domain_str: str) -> bool:
    """Checks if a domain or registered domain belongs to a known ESP infrastructure domain."""
    if not domain_str:
        return False
    
    clean = domain_str.strip().lower()
    esp_list = load_known_esp_domains()
    
    bd = parse_domain_structure(clean)
    reg_dom = bd.registered_domain.lower() if bd and bd.registered_domain else clean

    for esp in esp_list:
        esp_clean = esp.lower()
        if reg_dom == esp_clean or reg_dom.endswith("." + esp_clean) or clean.endswith("." + esp_clean):
            return True
    return False



@dataclass
class DomainBreakdown:
    """Accurate structural decomposition of a domain using tldextract."""
    raw_domain: str
    subdomain: str
    domain: str             # e.g., "paypal", "security-check"
    suffix: str             # e.g., "co.uk", "ru"
    registered_domain: str  # e.g., "paypal.co.uk", "security-check.ru"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainIntelResult:
    """Result of domain intelligence analysis."""
    status: str             # 'SUCCESS' or 'Unable to analyze - invalid sender domain'
    domain_breakdown: Optional[DomainBreakdown] = None
    is_homograph: bool = False
    homograph_details: Optional[str] = None
    is_typosquat: bool = False
    typosquat_matched_brand: Optional[str] = None
    typosquat_distance: Optional[int] = None
    typosquat_details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'domain_breakdown': self.domain_breakdown.to_dict() if self.domain_breakdown else None,
            'is_homograph': self.is_homograph,
            'homograph_details': self.homograph_details,
            'is_typosquat': self.is_typosquat,
            'typosquat_matched_brand': self.typosquat_matched_brand,
            'typosquat_distance': self.typosquat_distance,
            'typosquat_details': self.typosquat_details,
        }


def load_brand_domains() -> List[str]:
    """
    Loads curated list of brand domains from brand_domains.json.
    Checked against N known brand domains (curated list of major financial, tech, and Indian banking brands).
    """
    if BRAND_DOMAINS_FILE.exists():
        try:
            with open(BRAND_DOMAINS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                brands = data.get('brands', [])
                logger.debug(f"Loaded {len(brands)} brand domains for typosquat analysis.")
                return [b.lower() for b in brands]
        except Exception as e:
            logger.warning(f"Error reading brand_domains.json: {e}")

    # Fallback inline brand list (~38 entries)
    return [
        "paypal", "microsoft", "google", "apple", "amazon", "netflix", "meta",
        "facebook", "instagram", "twitter", "linkedin", "github", "dropbox",
        "adobe", "cisco", "zoom", "yahoo", "outlook", "gmail", "hotmail",
        "bankofamerica", "chase", "wellsfargo", "citibank", "americanexpress",
        "mastercard", "visa", "stripe", "square", "sbi", "hdfcbank",
        "icicibank", "axisbank", "kotak", "pnb", "phonepe", "paytm", "razorpay"
    ]


def parse_domain_structure(raw_domain_str: str) -> Optional[DomainBreakdown]:
    """
    Splits domain into subdomain, domain (registered label), and suffix using tldextract.
    e.g. "paypal.com.security-check.ru" -> subdomain="paypal.com", domain="security-check", suffix="ru"
    """
    if not raw_domain_str or not isinstance(raw_domain_str, str):
        return None

    clean_str = raw_domain_str.strip().lower()
    if '<' in clean_str and '>' in clean_str:
        clean_str = clean_str.split('<')[-1].split('>')[0]
    if '@' in clean_str:
        clean_str = clean_str.split('@')[-1]
    
    clean_str = clean_str.strip('.')
    if not clean_str:
        return None

    if tldextract is None:
        # Fallback simple split if tldextract missing
        parts = clean_str.split('.')
        if len(parts) >= 2:
            return DomainBreakdown(
                raw_domain=clean_str,
                subdomain=".".join(parts[:-2]) if len(parts) > 2 else "",
                domain=parts[-2],
                suffix=parts[-1],
                registered_domain=".".join(parts[-2:])
            )
        return None

    extracted = tldextract.extract(clean_str)
    if not extracted.domain or not extracted.suffix:
        return None

    return DomainBreakdown(
        raw_domain=clean_str,
        subdomain=extracted.subdomain,
        domain=extracted.domain,
        suffix=extracted.suffix,
        registered_domain=extracted.registered_domain or f"{extracted.domain}.{extracted.suffix}"
    )


def get_character_script(char: str) -> str:
    """Returns the script category name of a unicode character."""
    try:
        name = unicodedata.name(char, "")
        if "CYRILLIC" in name:
            return "Cyrillic"
        elif "GREEK" in name:
            return "Greek"
        elif "LATIN" in name:
            return "Latin"
        elif "ARABIC" in name:
            return "Arabic"
        elif "HEBREW" in name:
            return "Hebrew"
        elif "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
            return "Asian"
        elif char.isdigit() or char in ("-", ".", "_"):
            return "Common"
        return "Other"
    except Exception:
        return "Unknown"


def detect_homograph(domain_str: str) -> Tuple[bool, Optional[str]]:
    """
    Detects Punycode (xn--) and mixed-script homograph attacks using idna and unicodedata.
    Returns tuple: (is_homograph: bool, details: Optional[str]).
    """
    if not domain_str:
        return False, None

    clean_domain = domain_str.strip().lower()

    # 1. Punycode (xn--) check
    if 'xn--' in clean_domain:
        try:
            decoded = idna.decode(clean_domain)
            return True, f"Punycode/homograph domain detected: '{clean_domain}' decodes to '{decoded}'"
        except Exception as e:
            return True, f"Punycode prefix 'xn--' present in '{clean_domain}' (IDNA decode: {e})"

    # 2. Mixed-script detection (e.g. Cyrillic mixed with Latin)
    scripts_found = set()
    for char in clean_domain:
        if char not in ('.', '-'):
            script = get_character_script(char)
            if script not in ("Common", "Unknown"):
                scripts_found.add(script)

    if len(scripts_found) > 1:
        script_list_str = " + ".join(sorted(scripts_found))
        return True, f"Mixed-script domain detected ({script_list_str}): '{clean_domain}'"

    return False, None


def detect_typosquat(domain_label: str, brand_list: List[str]) -> Tuple[bool, Optional[str], Optional[int], Optional[str]]:
    """
    Detects typosquatting by comparing the sender's domain label against known brands using
    Levenshtein distance and normalized similarity (rapidfuzz).
    Returns tuple: (is_typosquat: bool, matched_brand: Optional[str], distance: Optional[int], details: Optional[str]).
    """
    if not domain_label or not brand_list:
        return False, None, None, None

    if Levenshtein is None:
        logger.warning("rapidfuzz library is not installed; skipping Levenshtein typosquat check.")
        return False, None, None, "rapidfuzz library unavailable"

    clean_label = domain_label.strip().lower()

    # Tokenize compound labels like "paypa1-security" or "paypa1"
    sub_tokens = [clean_label]
    if '-' in clean_label:
        sub_tokens.extend([t for t in clean_label.split('-') if len(t) >= 3])

    best_match_brand: Optional[str] = None
    min_dist: Optional[int] = None
    best_sim: Optional[float] = None

    for brand in brand_list:
        brand_clean = brand.lower()

        # If exact match, sender domain IS the brand -> NOT a typosquat!
        if clean_label == brand_clean:
            return False, None, None, None

        for token in sub_tokens:
            if token == brand_clean:
                continue

            # Substring check: if token is a substring of brand (e.g. 'mail' in 'gmail', 'pay' in 'paypal'),
            # or brand is a substring of token, it is a sub-word/phrase, not a typosquatting edit.
            if token in brand_clean or brand_clean in token:
                continue

            # Length difference filter: token vs brand length must be within 2 characters
            if abs(len(token) - len(brand_clean)) > 2:
                continue

            dist = Levenshtein.distance(token, brand_clean)

            # Compute normalized similarity (0.0 to 1.0)
            if hasattr(Levenshtein, 'normalized_similarity'):
                sim = Levenshtein.normalized_similarity(token, brand_clean)
            else:
                max_len = max(len(token), len(brand_clean))
                sim = 1.0 - (dist / max_len) if max_len > 0 else 0.0

            # Flag ONLY IF raw distance is 1 or 2 AND normalized similarity is >= 0.80 (80%)
            if dist in (1, 2) and sim >= 0.80:
                if min_dist is None or dist < min_dist or (dist == min_dist and (best_sim is None or sim > best_sim)):
                    min_dist = dist
                    best_sim = sim
                    best_match_brand = brand_clean

    if best_match_brand and min_dist is not None and best_sim is not None:
        sim_pct = round(best_sim * 100, 1)
        details = (
            f"Typosquatting detected: domain label '{clean_label}' matched monitored brand '{best_match_brand}' "
            f"(Levenshtein distance {min_dist}, normalized similarity {sim_pct}%). "
            f"(Checked against {len(brand_list)} known brand domains)."
        )
        return True, best_match_brand, min_dist, details

    return False, None, None, None


def run_domain_intel(parsed_email: ParsedEmail) -> DomainIntelResult:
    """
    Main entry point for Domain Intelligence Layer.
    Extracts From domain, parses structure via tldextract, checks homograph/punycode, and checks typosquatting.
    """
    raw_from_address = parsed_email.from_address or parsed_email.return_path
    if not raw_from_address:
        return DomainIntelResult(
            status="Unable to analyze - invalid sender domain",
            domain_breakdown=None
        )

    breakdown = parse_domain_structure(raw_from_address)
    if not breakdown or not breakdown.domain:
        return DomainIntelResult(
            status="Unable to analyze - invalid sender domain",
            domain_breakdown=None
        )

    # 1. Homograph / Punycode check
    is_homograph, homograph_details = detect_homograph(breakdown.raw_domain)

    # 2. Typosquat check
    brand_list = load_brand_domains()
    is_typosquat, matched_brand, distance, typosquat_details = detect_typosquat(breakdown.domain, brand_list)

    return DomainIntelResult(
        status="SUCCESS",
        domain_breakdown=breakdown,
        is_homograph=is_homograph,
        homograph_details=homograph_details,
        is_typosquat=is_typosquat,
        typosquat_matched_brand=matched_brand,
        typosquat_distance=distance,
        typosquat_details=typosquat_details
    )
