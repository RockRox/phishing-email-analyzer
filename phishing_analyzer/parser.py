"""Parse .eml files into a structured ParsedEmail object."""
import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import List, Dict, Any


@dataclass
class ParsedEmail:
    message: EmailMessage
    subject: str
    from_header: str
    reply_to: str
    return_path: str
    to: str
    text_body: str = ""
    html_body: str = ""
    attachments: List[Dict[str, Any]] = field(default_factory=list)

    def header(self, name: str) -> str:
        value = self.message.get(name, "")
        return str(value) if value else ""

    def all_headers(self, name: str) -> List[str]:
        return [str(v) for v in self.message.get_all(name, [])]


def parse_eml(path: str) -> ParsedEmail:
    """Parse an .eml file from disk."""
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parsed = ParsedEmail(
        message=msg,
        subject=str(msg.get("Subject", "") or ""),
        from_header=str(msg.get("From", "") or ""),
        reply_to=str(msg.get("Reply-To", "") or ""),
        return_path=str(msg.get("Return-Path", "") or ""),
        to=str(msg.get("To", "") or ""),
    )

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append({
                "filename": filename or "(unnamed)",
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),  # noqa: S324 (IOC lookups only)
                "head": payload[:8],
            })
            continue

        try:
            content = part.get_content()
        except Exception:  # malformed charset etc.
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")

        if ctype == "text/plain":
            parsed.text_body += content
        elif ctype == "text/html":
            parsed.html_body += content
    return parsed
