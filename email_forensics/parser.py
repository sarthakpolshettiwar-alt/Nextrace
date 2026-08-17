"""
email_forensics/parser.py

Parsing foundation for Email Forensic Analysis in Forenix.
Parses .eml and .msg files into a unified internal ParsedEmail data structure.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from email.message import EmailMessage
import email
import email.policy
import email.utils
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import logging

try:
    import extract_msg
except ImportError:
    extract_msg = None

logger = logging.getLogger(__name__)


class EmailParserError(Exception):
    """Base exception for email parser errors."""
    pass


class InvalidEmailFileError(EmailParserError):
    """Raised when an email file (.eml or .msg) is missing, corrupt, or unparseable."""
    pass


@dataclass
class EmailAttachment:
    """Represents metadata and decoded content bytes for an email attachment."""
    filename: Optional[str]
    size: int  # Size in bytes
    content: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'size': self.size,
            'has_content': self.content is not None
        }


@dataclass
class ParsedEmail:
    """
    Unified internal representation of a parsed email.
    Downstream forensic engines consume this exact structure regardless of source format (.eml or .msg).
    """
    from_name: Optional[str]
    from_address: Optional[str]
    to: Optional[str]
    subject: Optional[str]
    date: Optional[datetime]
    return_path: Optional[str]
    reply_to: Optional[str]
    message_id: Optional[str]
    received_headers: List[str] = field(default_factory=list)
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[EmailAttachment] = field(default_factory=list)
    all_headers: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:

        """Convert ParsedEmail instance to a clean dictionary, ensuring raw attachment bytes are excluded."""
        return {
            'from_name': self.from_name,
            'from_address': self.from_address,
            'to': self.to,
            'subject': self.subject,
            'date': self.date.isoformat() if self.date else None,
            'return_path': self.return_path,
            'reply_to': self.reply_to,
            'message_id': self.message_id,
            'received_headers': list(self.received_headers),
            'body_plain': self.body_plain,
            'body_html': self.body_html,
            'attachments': [att.to_dict() for att in self.attachments],
            'all_headers': self.all_headers,
        }



def _parse_datetime_str(date_str: Optional[str]) -> Optional[datetime]:
    """Helper to safely parse RFC 2822 or ISO date strings into a datetime object."""
    if not date_str or not isinstance(date_str, str):
        return None
    
    date_str = date_str.strip()
    if not date_str:
        return None

    # Try standard email parsedate_to_datetime
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt:
            return dt
    except (ValueError, TypeError, OverflowError, IndexError):
        pass

    # Fallback to dateutil if available
    try:
        from dateutil import parser as dateutil_parser
        return dateutil_parser.parse(date_str)
    except Exception:
        pass

    return None


def parse_eml(file_source: Union[str, Path, bytes]) -> ParsedEmail:
    """
    Parse an EML file or raw bytes using Python's built-in email module with email.policy.default.

    :param file_source: Path to .eml file or raw bytes content.
    :return: ParsedEmail instance.
    :raises InvalidEmailFileError: If the file cannot be read or parsed.
    """
    try:
        if isinstance(file_source, bytes):
            raw_bytes = file_source
        else:
            filepath = Path(file_source)
            if not filepath.exists() or not filepath.is_file():
                raise InvalidEmailFileError(f"EML file does not exist: {file_source}")
            with open(filepath, 'rb') as f:
                raw_bytes = f.read()

        if not raw_bytes or not raw_bytes.strip():
            raise InvalidEmailFileError("EML file content is empty.")

        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        if len(msg.keys()) == 0:
            raise InvalidEmailFileError("EML file does not contain valid email headers.")

    except InvalidEmailFileError:
        raise
    except Exception as e:
        raise InvalidEmailFileError(f"Failed to parse EML content: {e}") from e

    # Extract headers
    from_header = msg.get('From')
    from_name: Optional[str] = None
    from_address: Optional[str] = None

    if from_header:
        # Check header parse
        raw_name, raw_addr = email.utils.parseaddr(str(from_header))
        from_name = raw_name.strip() if raw_name and raw_name.strip() else None
        from_address = raw_addr.strip() if raw_addr and raw_addr.strip() else None
        
        # If parseaddr failed to separate name/address, use string fallback
        if not from_address and '@' in str(from_header):
            from_address = str(from_header).strip()

    to_header = msg.get('To')
    to_val: Optional[str] = str(to_header).strip() if to_header else None

    subject_header = msg.get('Subject')
    subject_val: Optional[str] = str(subject_header).strip() if subject_header else None

    date_header = msg.get('Date')
    date_val: Optional[datetime] = None
    if date_header:
        date_val = _parse_datetime_str(str(date_header))

    return_path_header = msg.get('Return-Path')
    return_path_val: Optional[str] = str(return_path_header).strip() if return_path_header else None

    reply_to_header = msg.get('Reply-To')
    reply_to_val: Optional[str] = str(reply_to_header).strip() if reply_to_header else None

    message_id_header = msg.get('Message-ID')
    message_id_val: Optional[str] = str(message_id_header).strip() if message_id_header else None

    # All Received headers in order
    received_raw = msg.get_all('Received') or []
    received_headers: List[str] = [str(hdr).strip() for hdr in received_raw if hdr]

    # Extract bodies and attachments
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[EmailAttachment] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get_content_disposition() or '')
                filename = part.get_filename()
                content_type = part.get_content_type()

                if content_disposition == 'attachment' or (filename and content_type not in ('multipart/mixed', 'multipart/alternative', 'multipart/related')):
                    # Attachment
                    att_bytes = part.get_payload(decode=True)
                    att_size = len(att_bytes) if att_bytes is not None else 0
                    attachments.append(EmailAttachment(
                        filename=str(filename).strip() if filename else None,
                        size=att_size,
                        content=att_bytes if isinstance(att_bytes, bytes) else None
                    ))
                else:
                    if content_type == 'text/plain' and body_plain is None and content_disposition != 'attachment':
                        try:
                            body_plain = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                body_plain = payload.decode(errors='replace')
                    elif content_type == 'text/html' and body_html is None and content_disposition != 'attachment':
                        try:
                            body_html = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                body_html = payload.decode(errors='replace')
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                content = payload.decode(errors='replace') if isinstance(payload, bytes) else str(payload)

            if content_type == 'text/html':
                body_html = content
            else:
                body_plain = content
    except Exception as e:
        logger.warning(f"Error reading body/attachments from EML: {e}")

    # Extract all raw headers in original order
    all_headers: List[Dict[str, str]] = [{'name': str(k), 'value': str(v)} for k, v in msg.items()]

    return ParsedEmail(
        from_name=from_name,
        from_address=from_address,
        to=to_val,
        subject=subject_val,
        date=date_val,
        return_path=return_path_val,
        reply_to=reply_to_val,
        message_id=message_id_val,
        received_headers=received_headers,
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
        all_headers=all_headers,
    )



def parse_msg(file_source: Union[str, Path, bytes]) -> ParsedEmail:
    """
    Parse an Outlook MSG file using extract-msg.

    :param file_source: Path to .msg file or bytes.
    :return: ParsedEmail instance.
    :raises InvalidEmailFileError: If file cannot be parsed or extract-msg is not installed.
    """
    if extract_msg is None:
        raise InvalidEmailFileError("extract-msg library is not installed.")

    msg_obj = None
    try:
        if isinstance(file_source, bytes):
            msg_obj = extract_msg.openMsg(file_source)
        else:
            filepath = Path(file_source)
            if not filepath.exists() or not filepath.is_file():
                raise InvalidEmailFileError(f"MSG file does not exist: {file_source}")
            msg_obj = extract_msg.Message(str(filepath))

        # Basic sanity check on extracted object
        if msg_obj is None:
            raise InvalidEmailFileError("Failed to initialize MSG object.")

    except InvalidEmailFileError:
        raise
    except Exception as e:
        raise InvalidEmailFileError(f"Failed to open/parse MSG file: {e}") from e

    try:
        # Sender details
        raw_sender_name = getattr(msg_obj, 'senderName', None) or getattr(msg_obj, 'sender', None)
        raw_sender_email = getattr(msg_obj, 'senderEmail', None)

        from_name: Optional[str] = str(raw_sender_name).strip() if raw_sender_name else None
        from_address: Optional[str] = str(raw_sender_email).strip() if raw_sender_email else None

        if from_name:
            n, a = email.utils.parseaddr(from_name)
            if a:
                from_address = from_address or a.strip()
                from_name = n.strip() if n else None

        if not from_address and raw_sender_email:
            n, a = email.utils.parseaddr(str(raw_sender_email))
            from_address = a.strip() if a else str(raw_sender_email).strip()

        # Transport headers fallback parser
        transport_headers_raw = getattr(msg_obj, 'transportHeaders', None) or ""
        header_msg = None
        if transport_headers_raw:
            try:
                header_msg = email.message_from_string(str(transport_headers_raw), policy=email.policy.default)
            except Exception:
                pass

        # Recipient
        to_val: Optional[str] = getattr(msg_obj, 'to', None) or getattr(msg_obj, 'displayTo', None)
        if not to_val and header_msg and header_msg.get('To'):
            to_val = str(header_msg.get('To')).strip()
        elif to_val:
            to_val = str(to_val).strip()

        # Subject
        subj = getattr(msg_obj, 'subject', None)
        subject_val: Optional[str] = None
        if subj:
            subject_val = str(subj).strip()
        elif header_msg and header_msg.get('Subject'):
            subject_val = str(header_msg.get('Subject')).strip()

        # Date
        date_raw = getattr(msg_obj, 'date', None)
        date_val: Optional[datetime] = None
        if isinstance(date_raw, datetime):
            date_val = date_raw
        elif isinstance(date_raw, str):
            date_val = _parse_datetime_str(date_raw)
        
        if not date_val and header_msg and header_msg.get('Date'):
            date_val = _parse_datetime_str(str(header_msg.get('Date')))

        # Return-Path
        return_path_val: Optional[str] = None
        if header_msg and header_msg.get('Return-Path'):
            return_path_val = str(header_msg.get('Return-Path')).strip()
        elif hasattr(msg_obj, 'returnPath') and getattr(msg_obj, 'returnPath'):
            return_path_val = str(getattr(msg_obj, 'returnPath')).strip()

        # Reply-To
        reply_to_val: Optional[str] = None
        if header_msg and header_msg.get('Reply-To'):
            reply_to_val = str(header_msg.get('Reply-To')).strip()
        elif hasattr(msg_obj, 'replyTo') and getattr(msg_obj, 'replyTo'):
            reply_to_val = str(getattr(msg_obj, 'replyTo')).strip()

        # Message-ID
        message_id_val: Optional[str] = None
        if getattr(msg_obj, 'messageId', None):
            message_id_val = str(getattr(msg_obj, 'messageId')).strip()
        elif header_msg and header_msg.get('Message-ID'):
            message_id_val = str(header_msg.get('Message-ID')).strip()


        # Received headers
        received_headers: List[str] = []
        if header_msg:
            rec_list = header_msg.get_all('Received') or []
            received_headers = [str(r).strip() for r in rec_list if r]
        elif hasattr(msg_obj, 'header') and hasattr(msg_obj.header, 'get_all'):
            rec_list = msg_obj.header.get_all('Received') or []
            received_headers = [str(r).strip() for r in rec_list if r]

        # Bodies
        body_plain: Optional[str] = getattr(msg_obj, 'body', None)
        if body_plain is not None:
            body_plain = str(body_plain)
            if not body_plain.strip():
                body_plain = None

        body_html: Optional[str] = None
        html_raw = getattr(msg_obj, 'htmlBody', None)
        if html_raw:
            if isinstance(html_raw, bytes):
                try:
                    body_html = html_raw.decode('utf-8')
                except UnicodeDecodeError:
                    body_html = html_raw.decode('latin-1', errors='replace')
            else:
                body_html = str(html_raw)

        # Attachments
        attachments: List[EmailAttachment] = []
        msg_attachments = getattr(msg_obj, 'attachments', []) or []
        for att in msg_attachments:
            fname = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or getattr(att, 'filename', None)
            att_data = getattr(att, 'data', None)
            if not isinstance(att_data, bytes):
                att_data = None
            att_size = len(att_data) if att_data is not None else (att.size if hasattr(att, 'size') and isinstance(att.size, int) else 0)
            
            attachments.append(EmailAttachment(
                filename=str(fname).strip() if fname else None,
                size=att_size,
                content=att_data
            ))

        all_headers: List[Dict[str, str]] = []
        if header_msg:
            all_headers = [{'name': str(k), 'value': str(v)} for k, v in header_msg.items()]

        return ParsedEmail(
            from_name=from_name,
            from_address=from_address,
            to=to_val,
            subject=subject_val,
            date=date_val,
            return_path=return_path_val,
            reply_to=reply_to_val,
            message_id=message_id_val,
            received_headers=received_headers,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            all_headers=all_headers,
        )

    except Exception as e:
        raise InvalidEmailFileError(f"Error processing MSG file structure: {e}") from e
    finally:
        if msg_obj and hasattr(msg_obj, 'close'):
            try:
                msg_obj.close()
            except Exception:
                pass


def parse_email_file(file_path: Union[str, Path]) -> ParsedEmail:
    """
    Unified dispatcher to parse either an EML or MSG file based on extension/signature.

    :param file_path: Path to email file (.eml or .msg).
    :return: ParsedEmail unified internal data structure.
    :raises InvalidEmailFileError: If file extension is unsupported or file is corrupted.
    """
    filepath = Path(file_path)
    if not filepath.exists() or not filepath.is_file():
        raise InvalidEmailFileError(f"File not found: {file_path}")

    ext = filepath.suffix.lower()

    if ext == '.eml':
        return parse_eml(filepath)
    elif ext == '.msg':
        return parse_msg(filepath)
    else:
        # Attempt signature fallback if unknown extension
        try:
            with open(filepath, 'rb') as f:
                header_bytes = f.read(8)
            # OLE2 Compound File Binary Format magic bytes for MSG: D0 CF 11 E0 A1 B1 1A E1
            if header_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                return parse_msg(filepath)
            else:
                return parse_eml(filepath)
        except Exception as e:
            raise InvalidEmailFileError(f"Unsupported or unrecognized email file format: {filepath.name} ({e})") from e
