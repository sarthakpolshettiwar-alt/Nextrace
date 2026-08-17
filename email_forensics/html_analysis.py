"""
email_forensics/html_analysis.py

HTML Content Analysis for Forenix Module 2.
Performs deterministic offline analysis on HTML body content using BeautifulSoup:
- Hidden text detection (display:none, visibility:hidden, font-size 0, matching font/background colors)
- Invisible / disguised links (empty <a> tags or 1x1 tracking pixels inside links)
- JavaScript redirect & meta-refresh detection
- Iframe tag detection
- Large obfuscated base64 data URI payload detection (>10KB)
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import re
import logging
from bs4 import BeautifulSoup, Tag
from .parser import ParsedEmail

logger = logging.getLogger(__name__)

# Regex patterns for HTML inline styles
STYLE_HIDDEN_REGEX = re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden', re.IGNORECASE)
STYLE_ZERO_FONT_REGEX = re.compile(r'font-size\s*:\s*0(?:px|pt|em|rem)?\b', re.IGNORECASE)

JS_REDIRECT_REGEX = re.compile(
    r'(?:window|document)\.location|location\.(?:href|replace|assign)\b',
    re.IGNORECASE
)


@dataclass
class HTMLAnalysisResult:
    """Stores findings from HTML Content Analysis."""
    has_hidden_text: bool = False
    hidden_text_evidence: List[str] = field(default_factory=list)
    
    has_invisible_links: bool = False
    invisible_links_evidence: List[str] = field(default_factory=list)
    
    has_js_redirect: bool = False
    js_redirect_evidence: List[str] = field(default_factory=list)
    
    has_iframe: bool = False
    iframe_evidence: List[str] = field(default_factory=list)
    
    has_large_base64: bool = False
    base64_evidence: List[str] = field(default_factory=list)
    
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _truncate_snippet(snippet: str, max_len: int = 150) -> str:
    """Helper to truncate long HTML snippets for display."""
    clean = snippet.strip().replace('\n', ' ').replace('\r', '')
    if len(clean) > max_len:
        return clean[:max_len] + '...'
    return clean


def run_html_analysis(parsed_email: ParsedEmail) -> HTMLAnalysisResult:
    """
    Analyzes the HTML body of a parsed email for suspicious structural patterns.

    :param parsed_email: ParsedEmail instance.
    :return: HTMLAnalysisResult object.
    """
    result = HTMLAnalysisResult()
    findings = []

    html_body = parsed_email.body_html
    if not html_body or not html_body.strip():
        return result

    try:
        soup = BeautifulSoup(html_body, 'html.parser')
    except Exception as e:
        logger.warning(f"Failed to parse HTML body with BeautifulSoup: {e}")
        return result

    # 1. Hidden Text Detection
    hidden_snippets = []
    for tag in soup.find_all(True):
        style_attr = tag.get('style', '')
        if isinstance(style_attr, list):
            style_attr = ' '.join(style_attr)
        
        style_str = str(style_attr)

        # Check display:none or visibility:hidden
        if STYLE_HIDDEN_REGEX.search(style_str):
            text_content = tag.get_text(strip=True)
            if text_content:
                snippet = _truncate_snippet(str(tag))
                hidden_snippets.append(f"Hidden element ({snippet}): '{text_content[:60]}'")

        # Check font-size:0
        elif STYLE_ZERO_FONT_REGEX.search(style_str) or tag.get('size') == '0':
            text_content = tag.get_text(strip=True)
            if text_content:
                snippet = _truncate_snippet(str(tag))
                hidden_snippets.append(f"Zero font-size element ({snippet}): '{text_content[:60]}'")

        # Check matching font color & background color in inline style
        elif style_str:
            color_match = re.search(r'(?:^|;)\s*color\s*:\s*([^;]+)', style_str, re.IGNORECASE)
            bg_match = re.search(r'(?:^|;)\s*background(?:-color)?\s*:\s*([^;]+)', style_str, re.IGNORECASE)
            if color_match and bg_match:
                c_val = color_match.group(1).strip().lower()
                bg_val = bg_match.group(1).strip().lower()
                if c_val == bg_val and len(c_val) > 0 and tag.get_text(strip=True):
                    snippet = _truncate_snippet(str(tag))
                    hidden_snippets.append(f"Same font & background color ({c_val}): '{tag.get_text(strip=True)[:60]}'")

    if hidden_snippets:
        result.has_hidden_text = True
        result.hidden_text_evidence = hidden_snippets
        findings.append({
            'rule': 'Hidden Text Detected',
            'severity': 'HIGH',
            'evidence': hidden_snippets[0]
        })

    # 2. Invisible / Disguised Links
    invisible_links = []
    for a_tag in soup.find_all('a'):
        href = a_tag.get('href', '')
        text = a_tag.get_text(strip=True)
        imgs = a_tag.find_all('img')

        is_invisible = False
        reason = ""

        # Case A: Empty text and no images
        if not text and not imgs:
            is_invisible = True
            reason = "Link has no visible anchor text or image"

        # Case B: Contains 1x1 tracking image inside link
        elif imgs:
            for img in imgs:
                w = str(img.get('width', '')).strip()
                h = str(img.get('height', '')).strip()
                img_style = str(img.get('style', '')).strip().lower()

                if w in ('1', '0', '1px', '0px') or h in ('1', '0', '1px', '0px') or 'width:1px' in img_style or 'height:1px' in img_style:
                    is_invisible = True
                    reason = f"Link contains 1x1 pixel image ({img})"
                    break

        if is_invisible:
            snippet = _truncate_snippet(str(a_tag))
            invisible_links.append(f"{reason} -> {snippet}")

    if invisible_links:
        result.has_invisible_links = True
        result.invisible_links_evidence = invisible_links
        findings.append({
            'rule': 'Invisible / Disguised Link',
            'severity': 'HIGH',
            'evidence': invisible_links[0]
        })

    # 3. JavaScript Redirect & Meta Refresh Detection
    js_redirects = []
    # Check <script> tags
    for script_tag in soup.find_all('script'):
        script_code = script_tag.string or script_tag.get_text() or ""
        if JS_REDIRECT_REGEX.search(script_code):
            snippet = _truncate_snippet(script_code)
            js_redirects.append(f"Script redirect code: {snippet}")

    # Check <meta http-equiv="refresh"> tags
    for meta_tag in soup.find_all('meta'):
        http_equiv = str(meta_tag.get('http-equiv', '')).lower()
        if http_equiv == 'refresh':
            content = str(meta_tag.get('content', ''))
            js_redirects.append(f"Meta refresh tag: {content}")

    if js_redirects:
        result.has_js_redirect = True
        result.js_redirect_evidence = js_redirects
        findings.append({
            'rule': 'JavaScript / Meta Redirect',
            'severity': 'HIGH',
            'evidence': js_redirects[0]
        })

    # 4. Iframe Tag Detection
    iframes = []
    for iframe_tag in soup.find_all('iframe'):
        src = iframe_tag.get('src', '')
        snippet = _truncate_snippet(str(iframe_tag))
        iframes.append(f"<iframe> src='{src}': {snippet}")

    if iframes:
        result.has_iframe = True
        result.iframe_evidence = iframes
        findings.append({
            'rule': 'HTML Iframe Present',
            'severity': 'MEDIUM',
            'evidence': iframes[0]
        })

    # 5. Large Embedded Base64 Data Payload Detection (> 10KB)
    large_b64 = []
    # Search elements with src or href or inline style containing data: URIs
    for tag in soup.find_all(True):
        for attr in ('src', 'href'):
            attr_val = str(tag.get(attr, ''))
            if attr_val.startswith('data:') and ';base64,' in attr_val:
                b64_part = attr_val.split(';base64,', 1)[1]
                payload_len = len(b64_part)
                if payload_len > 10000:
                    large_b64.append(f"Large Base64 payload in <{tag.name} {attr}> ({payload_len} chars)")

    if large_b64:
        result.has_large_base64 = True
        result.base64_evidence = large_b64
        findings.append({
            'rule': 'Large Base64 Payload',
            'severity': 'MEDIUM',
            'evidence': large_b64[0]
        })

    result.findings = findings
    return result
