"""Email header checks: authentication results, spoofing indicators, routing."""
import re
from email.utils import parseaddr
from typing import List

from .models import Finding
from .parser import ParsedEmail


def _domain(addr: str) -> str:
    email_addr = parseaddr(addr)[1]
    return email_addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in email_addr else ""


def _registered(domain: str) -> str:
    """Naive registrable-domain guess (last two labels; handles common 2-level TLDs)."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _auth_result(auth_headers: List[str], mechanism: str) -> str:
    for header in auth_headers:
        match = re.search(rf"\b{mechanism}\s*=\s*([a-zA-Z]+)", header, re.I)
        if match:
            return match.group(1).lower()
    return "none"


def analyze_headers(email: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []

    # --- SPF / DKIM / DMARC -------------------------------------------------
    auth_headers = email.all_headers("Authentication-Results")
    received_spf = email.header("Received-SPF")
    if not auth_headers and not received_spf:
        findings.append(Finding(
            "header", "low", "No authentication results present",
            "No Authentication-Results/Received-SPF header found; SPF/DKIM/DMARC could not be verified."))
    else:
        for mech in ("spf", "dkim", "dmarc"):
            result = _auth_result(auth_headers, mech)
            if mech == "spf" and result == "none" and received_spf:
                result = received_spf.split()[0].lower()
            if result in {"fail", "softfail", "permerror", "temperror"}:
                sev = "high" if result == "fail" else "medium"
                findings.append(Finding("header", sev, f"{mech.upper()} {result}",
                                        f"{mech.upper()} check returned '{result}'."))
            elif result in {"none", "neutral"}:
                findings.append(Finding("header", "low", f"{mech.upper()} {result}",
                                        f"{mech.upper()} did not pass ('{result}')."))
            elif result == "pass":
                findings.append(Finding("header", "info", f"{mech.upper()} pass"))

    # --- Sender consistency ---------------------------------------------------
    from_dom = _domain(email.from_header)
    reply_dom = _domain(email.reply_to)
    rpath_dom = _domain(email.return_path)

    if not from_dom:
        findings.append(Finding("header", "medium", "Missing or malformed From address", email.from_header))

    if reply_dom and from_dom and _registered(reply_dom) != _registered(from_dom):
        findings.append(Finding("header", "high", "Reply-To domain differs from From domain",
                                f"From: {from_dom} | Reply-To: {reply_dom}"))

    if rpath_dom and from_dom and _registered(rpath_dom) != _registered(from_dom):
        findings.append(Finding("header", "medium", "Return-Path domain differs from From domain",
                                f"From: {from_dom} | Return-Path: {rpath_dom}"))

    # Display-name spoofing: display name contains an address whose domain differs from the real one
    display, addr = parseaddr(email.from_header)
    shown = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display or "")
    if shown and from_dom and _registered(shown.group(1).lower()) != _registered(from_dom):
        findings.append(Finding("header", "high", "Display name impersonates a different address",
                                f"Display name '{display}' vs actual '{addr}'"))

    # --- Routing ---------------------------------------------------------------
    received = email.all_headers("Received")
    if len(received) > 8:
        findings.append(Finding("header", "low", "Unusually long relay chain", f"{len(received)} Received headers."))
    if not received:
        findings.append(Finding("header", "low", "No Received headers", "Message may have been fabricated or stripped."))

    if re.search(r"phpmailer|swiftmailer|mass|bulk|leaf", email.header("X-Mailer"), re.I):
        findings.append(Finding("header", "low", "Bulk/scripted mailer detected", email.header("X-Mailer")))

    return findings
