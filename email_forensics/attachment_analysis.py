"""
email_forensics/attachment_analysis.py

Attachment Risk Analysis Layer for Forenix Module 2 (Email Forensic Analysis).
Analyzes attachments for:
1. Double extensions (e.g. invoice.pdf.exe)
2. Dangerous extensions (against dangerous_extensions.json)
3. File signature (magic bytes) verification vs claimed filename extension
4. Size sanity checks (informational note for unusually small documents)
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Set
from pathlib import Path
import json
import logging

try:
    import magic
except ImportError:
    magic = None

try:
    import filetype
except ImportError:
    filetype = None

from .parser import ParsedEmail, EmailAttachment

logger = logging.getLogger(__name__)

# Path to dangerous extensions JSON file
DANGEROUS_EXT_FILE = Path(__file__).parent / "dangerous_extensions.json"

# Common document/media extensions that spoofers disguise with dangerous double-extensions
DOCUMENT_MEDIA_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".csv", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".mp3"
}


@dataclass
class AttachmentAnalysisItem:
    """Detailed risk analysis result for a single email attachment."""
    filename: Optional[str]
    size: int
    claimed_extension: str
    detected_mime: str
    is_double_extension: bool = False
    double_ext_details: Optional[str] = None
    is_dangerous_extension: bool = False
    dangerous_ext_details: Optional[str] = None
    is_signature_mismatch: bool = False
    signature_mismatch_details: Optional[str] = None
    size_sanity_note: Optional[str] = None
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttachmentAnalysisResult:
    """Result container for Attachment Risk Analysis Layer."""
    status: str  # 'SUCCESS' or 'Unable to analyze - [reason]'
    attachments: List[AttachmentAnalysisItem] = field(default_factory=list)
    total_attachments: int = 0
    suspicious_attachments_count: int = 0
    has_dangerous_extension: bool = False
    has_double_extension: bool = False
    has_signature_mismatch: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'attachments': [a.to_dict() for a in self.attachments],
            'total_attachments': self.total_attachments,
            'suspicious_attachments_count': self.suspicious_attachments_count,
            'has_dangerous_extension': self.has_dangerous_extension,
            'has_double_extension': self.has_double_extension,
            'has_signature_mismatch': self.has_signature_mismatch,
        }


def load_dangerous_extensions() -> Set[str]:
    """Loads curated list of dangerous attachment extensions from dangerous_extensions.json."""
    if DANGEROUS_EXT_FILE.exists():
        try:
            with open(DANGEROUS_EXT_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                exts = data.get('dangerous_extensions', [])
                return {e.lower() for e in exts}
        except Exception as e:
            logger.warning(f"Error reading dangerous_extensions.json: {e}")

    # Default fallback list
    return {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".msi", ".jar", ".ps1", ".lnk"
    }


def detect_double_extension(filename: Optional[str], dangerous_exts: Set[str]) -> Tuple[bool, Optional[str]]:
    """
    Detects double extension trick (e.g. "report.pdf.exe").
    Flags ONLY if second-to-last extension is a document/media type AND last extension is dangerous.
    Does NOT falsely trigger on legitimate multi-dot names like "quarterly.report.v2.pdf".
    """
    if not filename or not isinstance(filename, str):
        return False, None

    clean_name = filename.strip().lower()
    parts = clean_name.split('.')
    if len(parts) < 3:
        return False, None

    last_ext = f".{parts[-1]}"
    second_last_ext = f".{parts[-2]}"

    if second_last_ext in DOCUMENT_MEDIA_EXTENSIONS and last_ext in dangerous_exts:
        details = f"Double extension trick detected: claimed document extension '{second_last_ext}' disguised before dangerous extension '{last_ext}' in '{filename}'"
        return True, details

    return False, None


def detect_magic_bytes(content: Optional[bytes]) -> Tuple[Optional[str], Optional[str]]:
    """
    Inspects actual first bytes of attachment to detect MIME type and description using python-magic or filetype.
    Returns tuple (mime_type: Optional[str], description: Optional[str]).
    """
    if content is None:
        return None, "Not available — attachment content not extracted"

    header_bytes = content[:4096]
    if not header_bytes:
        return "application/x-empty", "Empty file (0 bytes)"

    # Try python-magic first
    if magic is not None:
        try:
            detected_mime = magic.from_buffer(header_bytes, mime=True)
            if detected_mime:
                return detected_mime, f"Magic bytes identified MIME type: {detected_mime}"
        except Exception as e:
            logger.debug(f"python-magic detection error: {e}")

    # Fallback to pure-Python filetype library
    if filetype is not None:
        try:
            guess = filetype.guess(header_bytes)
            if guess:
                return guess.mime, f"filetype identified MIME type: {guess.mime}"
            else:
                return "application/octet-stream", "filetype: unknown binary payload"
        except Exception as e:
            logger.debug(f"filetype detection error: {e}")

    # Basic byte header fallback table if libraries fail
    if header_bytes.startswith(b'%PDF'):
        return "application/pdf", "Signature matched %PDF header"
    elif header_bytes.startswith(b'MZ'):
        return "application/x-dsexec", "Signature matched Windows MZ executable header"
    elif header_bytes.startswith(b'PK\x03\x04'):
        return "application/zip", "Signature matched PK zip/docx/xlsx archive header"
    elif header_bytes.startswith(b'\xff\xd8\xff'):
        return "image/jpeg", "Signature matched JPEG image header"
    elif header_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        return "image/png", "Signature matched PNG image header"

    return "application/octet-stream", "Unknown binary format"


def detect_signature_mismatch(claimed_ext: str, detected_mime: Optional[str], magic_details: str) -> Tuple[bool, Optional[str]]:
    """
    Compares claimed extension against detected magic byte MIME type.
    Flags mismatch if claimed extension conflicts with detected MIME type.
    """
    if detected_mime is None:
        return False, magic_details  # e.g., "Not available — attachment content not extracted"

    clean_ext = claimed_ext.lower().lstrip('.')
    if not clean_ext:
        return False, None

    exe_mimes = {"application/x-dsexec", "application/x-dosexec", "application/x-msdownload", "application/x-msdos-program", "application/x-executable"}

    if clean_ext in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "gif", "txt"):
        if detected_mime in exe_mimes:
            return True, f"File signature mismatch: claimed extension '.{clean_ext}' but actual file bytes contain Windows Executable (MZ header)!"

        if clean_ext == "pdf" and "pdf" not in detected_mime.lower() and detected_mime != "application/octet-stream":
            return True, f"File signature mismatch: claimed PDF ('.pdf') but actual content signature is '{detected_mime}'"

        if clean_ext in ("jpg", "jpeg", "png") and not detected_mime.startswith("image/") and detected_mime != "application/octet-stream":
            return True, f"File signature mismatch: claimed image ('.{clean_ext}') but actual content signature is '{detected_mime}'"

    return False, None


def check_size_sanity(claimed_ext: str, size: int) -> Optional[str]:
    """Informational note for unusually small documents (<100 bytes for PDF/DOCX/XLSX)."""
    clean_ext = claimed_ext.lower().lstrip('.')
    if clean_ext in ("pdf", "docx", "xlsx", "pptx") and size < 100:
        return f"Informational note: Unusually small size ({size} bytes) for claimed document type ('.{clean_ext}')"
    return None


def analyze_single_attachment(att: EmailAttachment, dangerous_exts: Set[str]) -> AttachmentAnalysisItem:
    """Analyzes a single EmailAttachment instance."""
    filename = att.filename or "unnamed_attachment"
    size = att.size
    flags: List[str] = []

    claimed_ext = Path(filename).suffix.lower() if '.' in filename else ""

    # 1. Double Extension Check
    is_double_ext, double_ext_details = detect_double_extension(filename, dangerous_exts)
    if is_double_ext and double_ext_details:
        flags.append(double_ext_details)

    # 2. Dangerous Extension Check
    is_dangerous_ext = False
    dangerous_ext_details: Optional[str] = None
    if claimed_ext in dangerous_exts:
        is_dangerous_ext = True
        dangerous_ext_details = f"Dangerous attachment extension detected: '{claimed_ext}' (high risk executable/script type)"
        flags.append(dangerous_ext_details)

    # 3. Magic Bytes Signature Check
    detected_mime, magic_details = detect_magic_bytes(att.content)
    is_mismatch = False
    signature_mismatch_details: Optional[str] = None

    if att.content is None:
        signature_mismatch_details = "Not available — attachment content not extracted"
    else:
        is_mismatch, signature_mismatch_details = detect_signature_mismatch(claimed_ext, detected_mime, magic_details)
        if is_mismatch and signature_mismatch_details:
            flags.append(signature_mismatch_details)

    # 4. Size Sanity Check (Informational only)
    size_note = check_size_sanity(claimed_ext, size)

    return AttachmentAnalysisItem(
        filename=filename,
        size=size,
        claimed_extension=claimed_ext or "(none)",
        detected_mime=detected_mime or "Not available — attachment content not extracted",
        is_double_extension=is_double_ext,
        double_ext_details=double_ext_details,
        is_dangerous_extension=is_dangerous_ext,
        dangerous_ext_details=dangerous_ext_details,
        is_signature_mismatch=is_mismatch,
        signature_mismatch_details=signature_mismatch_details,
        size_sanity_note=size_note,
        flags=flags
    )


def run_attachment_analysis(parsed_email: ParsedEmail) -> AttachmentAnalysisResult:
    """
    Main entry point for Attachment Risk Analysis Layer.
    Processes all attachments extracted by parser.py and returns AttachmentAnalysisResult.
    """
    if not parsed_email or not parsed_email.attachments:
        return AttachmentAnalysisResult(
            status="SUCCESS",
            attachments=[],
            total_attachments=0,
            suspicious_attachments_count=0
        )

    dangerous_exts = load_dangerous_extensions()
    analyzed_items: List[AttachmentAnalysisItem] = []
    suspicious_count = 0

    has_dangerous_ext = False
    has_double_ext = False
    has_mismatch = False

    for att in parsed_email.attachments:
        item = analyze_single_attachment(att, dangerous_exts)
        if item.flags:
            suspicious_count += 1

        if item.is_dangerous_extension:
            has_dangerous_ext = True
        if item.is_double_extension:
            has_double_ext = True
        if item.is_signature_mismatch:
            has_mismatch = True

        analyzed_items.append(item)

    return AttachmentAnalysisResult(
        status="SUCCESS",
        attachments=analyzed_items,
        total_attachments=len(analyzed_items),
        suspicious_attachments_count=suspicious_count,
        has_dangerous_extension=has_dangerous_ext,
        has_double_extension=has_double_ext,
        has_signature_mismatch=has_mismatch
    )
