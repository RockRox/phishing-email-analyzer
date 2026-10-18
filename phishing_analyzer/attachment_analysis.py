"""Attachment inspection (static only - attachments are never executed or saved)."""
import os
from typing import List, Dict, Any

from .models import Finding

EXECUTABLE_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".ps1", ".jar", ".lnk", ".hta", ".cpl", ".reg", ".dll",
    ".iso", ".img", ".apk",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".csv"}

MAGIC = {
    b"MZ": "Windows executable (PE)",
    b"\x7fELF": "Linux executable (ELF)",
    b"PK\x03\x04": "ZIP-based container",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE2 (legacy Office)",
    b"Rar!": "RAR archive",
}


def _magic_type(head: bytes) -> str:
    for sig, label in MAGIC.items():
        if head.startswith(sig):
            return label
    return ""


def analyze_attachments(attachments: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    risky = EXECUTABLE_EXT | MACRO_EXT
    for att in attachments:
        name = att["filename"]
        lower = name.lower()
        base, ext = os.path.splitext(lower)
        _, inner_ext = os.path.splitext(base)
        tag = f"{name} (sha256 {att['sha256'][:16]}...)"

        if ext in EXECUTABLE_EXT:
            findings.append(Finding("attachment", "high", "Executable/script attachment", tag))
        elif ext in MACRO_EXT:
            findings.append(Finding("attachment", "high", "Macro-enabled Office attachment", tag))
        elif ext in ARCHIVE_EXT:
            findings.append(Finding("attachment", "medium", "Archive attachment (may hide payload)", tag))

        if inner_ext in DOC_EXT and ext in risky:
            findings.append(Finding("attachment", "high", "Double extension masquerading as document", name))

        magic = _magic_type(att.get("head", b""))
        if magic.startswith(("Windows executable", "Linux executable")) and ext not in EXECUTABLE_EXT:
            findings.append(Finding("attachment", "high", "File content is executable but extension is not",
                                    f"{name}: {magic}"))
        if ext == ".pdf" and magic and "PDF" not in magic:
            findings.append(Finding("attachment", "medium", "Extension/content mismatch", f"{name}: {magic}"))

        if len(name) > 100:
            findings.append(Finding("attachment", "low", "Very long attachment filename", name[:60] + "..."))
        if att["size"] == 0:
            findings.append(Finding("attachment", "low", "Empty attachment", name))
    return findings
