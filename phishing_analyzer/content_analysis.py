"""Body/subject content heuristics (social-engineering indicators)."""
import re
from html.parser import HTMLParser
from typing import List

from .models import Finding

URGENCY = [
    "urgent", "immediately", "action required", "within 24 hours", "within 48 hours",
    "final notice", "last warning", "account will be suspended", "account suspended",
    "will be closed", "expires today", "act now", "verify now", "limited time",
    "failure to comply", "unauthorized login", "unusual activity", "suspended",
]
CREDENTIALS = [
    "password", "verify your account", "confirm your identity", "login credentials",
    "social security", "ssn", "credit card", "card number", "cvv", "pin number",
    "bank account", "one-time password", "update your payment", "billing information",
]
FINANCIAL_LURES = [
    "wire transfer", "gift card", "invoice attached", "payment overdue", "refund",
    "lottery", "you have won", "inheritance", "bitcoin", "crypto wallet", "prize",
]
GENERIC_GREETINGS = ["dear customer", "dear user", "dear account holder", "dear member", "dear sir/madam", "valued customer"]


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: List[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    return " ".join(p.parts)


def _hits(haystack: str, needles: List[str]) -> List[str]:
    return [n for n in needles if n in haystack]


def analyze_content(subject: str, text_body: str, html_body: str) -> List[Finding]:
    findings: List[Finding] = []
    html_text = html_to_text(html_body) if html_body else ""
    haystack = f"{subject} {text_body or ''} {html_text}".lower()

    urg = _hits(haystack, URGENCY)
    if urg:
        sev = "high" if len(urg) >= 3 else "medium"
        findings.append(Finding("content", sev, "Urgency / pressure language", ", ".join(urg[:6])))

    cred = _hits(haystack, CREDENTIALS)
    if cred:
        sev = "high" if len(cred) >= 2 else "medium"
        findings.append(Finding("content", sev, "Requests for credentials or sensitive data", ", ".join(cred[:6])))

    lure = _hits(haystack, FINANCIAL_LURES)
    if lure:
        findings.append(Finding("content", "medium", "Financial lure keywords", ", ".join(lure[:6])))

    greet = _hits(haystack, GENERIC_GREETINGS)
    if greet:
        findings.append(Finding("content", "low", "Generic greeting", greet[0]))

    letters = re.findall(r"[A-Za-z]", subject)
    uppers = re.findall(r"[A-Z]", subject)
    if len(subject) > 8 and letters and len(uppers) > 0.6 * len(letters):
        findings.append(Finding("content", "low", "Subject is mostly uppercase", subject))
    if subject.count("!") >= 2:
        findings.append(Finding("content", "low", "Excessive exclamation marks in subject", subject))

    if html_body:
        if re.search(r"<form[^>]*>", html_body, re.I) and re.search(r'type=["\']?password', html_body, re.I):
            findings.append(Finding("content", "high", "Embedded password form in email body"))
        if re.search(r"<iframe", html_body, re.I):
            findings.append(Finding("content", "medium", "Embedded iframe in HTML body"))
        if re.search(r"<script", html_body, re.I):
            findings.append(Finding("content", "medium", "Script tag in HTML body"))
        if re.search(r"display\s*:\s*none|font-size\s*:\s*0", html_body, re.I):
            findings.append(Finding("content", "low", "Hidden text/elements in HTML body"))
        if not (text_body or "").strip() and len(html_text.strip()) < 20:
            findings.append(Finding("content", "low", "Image-only / near-empty body"))
    return findings
