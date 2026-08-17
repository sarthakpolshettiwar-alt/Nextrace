"""
email_forensics/content_analysis.py

Content & Keyword Analysis for Forenix Module 2.
Performs case-insensitive pattern matching against email body content using curated scam indicator terms.
Surfaces exact matched phrases, category groupings, and transparent disclaimers.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import re
import logging
from bs4 import BeautifulSoup
from .parser import ParsedEmail

logger = logging.getLogger(__name__)

KEYWORD_FILE_PATH = Path(__file__).parent / "scam_keywords.json"

DISCLAIMER_TEXT = (
    "Keyword-based check against curated phishing/scam indicator terms — presence of these words "
    "does not confirm malicious intent, especially in legitimate financial or HR correspondence; "
    "absence does not guarantee safety."
)


@dataclass
class KeywordMatchCategory:
    """Stores matched phrases for a single keyword category."""
    category_name: str
    matched_phrases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContentAnalysisResult:
    """Stores findings from Content & Keyword Analysis."""
    categories_flagged: List[KeywordMatchCategory] = field(default_factory=list)
    total_categories_count: int = 0
    total_matches_count: int = 0
    disclaimer: str = DISCLAIMER_TEXT
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _load_keywords() -> Dict[str, List[str]]:
    """Loads scam indicator terms from JSON file."""
    if not KEYWORD_FILE_PATH.exists():
        logger.error(f"Scam keywords file missing at {KEYWORD_FILE_PATH}")
        return {}
    try:
        with open(KEYWORD_FILE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load scam keywords JSON: {e}")
        return {}


def run_content_analysis(parsed_email: ParsedEmail) -> ContentAnalysisResult:
    """
    Evaluates body content against curated scam indicator term dictionary.

    :param parsed_email: ParsedEmail instance.
    :return: ContentAnalysisResult object.
    """
    result = ContentAnalysisResult()
    keywords_db = _load_keywords()
    if not keywords_db:
        return result

    # Aggregate body text (plaintext + HTML stripped text)
    body_text_parts = []
    if parsed_email.body_plain:
        body_text_parts.append(parsed_email.body_plain)

    if parsed_email.body_html:
        try:
            soup = BeautifulSoup(parsed_email.body_html, 'html.parser')
            body_text_parts.append(soup.get_text(separator=' '))
        except Exception:
            body_text_parts.append(parsed_email.body_html)

    full_body_text = ' '.join(body_text_parts).lower()
    if not full_body_text.strip():
        return result

    categories_flagged = []
    findings = []
    total_matches = 0

    for category, phrase_list in keywords_db.items():
        matched_in_cat = []
        for phrase in phrase_list:
            phrase_clean = phrase.strip().lower()
            if not phrase_clean:
                continue

            # Word boundary search if single word, or substring search if phrase
            if ' ' in phrase_clean:
                if phrase_clean in full_body_text:
                    matched_in_cat.append(phrase.strip())
            else:
                pattern = r'\b' + re.escape(phrase_clean) + r'\b'
                if re.search(pattern, full_body_text):
                    matched_in_cat.append(phrase.strip())

        if matched_in_cat:
            cat_obj = KeywordMatchCategory(
                category_name=category,
                matched_phrases=list(set(matched_in_cat))
            )
            categories_flagged.append(cat_obj)
            total_matches += len(cat_obj.matched_phrases)

            findings.append({
                'rule': f'Scam Keywords ({category.title()})',
                'severity': 'MEDIUM',
                'evidence': f"Category '{category}' matched: {', '.join(cat_obj.matched_phrases)}"
            })

    result.categories_flagged = categories_flagged
    result.total_categories_count = len(categories_flagged)
    result.total_matches_count = total_matches
    result.findings = findings

    return result
