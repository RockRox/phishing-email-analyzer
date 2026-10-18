"""URL extraction and heuristic scoring."""
import ipaddress
import re
from html.parser import HTMLParser
from typing import List, Tuple
from urllib.parse import urlparse

from .models import Finding

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "ml", "cf", "tk", "ga",
    "work", "support", "loan", "rest", "fit", "cam", "icu", "monster",
}
BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "google", "apple", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "dropbox", "docusign",
    "dhl", "fedex", "hdfc", "icici", "paytm", "wellsfargo",
    "bankofamerica", "binance", "coinbase",
]
CREDENTIAL_PATH_HINTS = ("login", "signin", "verify", "update", "secure", "account", "password", "confirm")


class _LinkParser(HTMLParser):
    """Collect (href, anchor_text) pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self._href = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def extract_urls(text_body: str, html_body: str) -> List[str]:
    urls: List[str] = []
    if html_body:
        parser = _LinkParser()
        parser.feed(html_body)
        urls.extend(h for h, _ in parser.links if h and h.lower().startswith(("http://", "https://")))
    urls.extend(URL_RE.findall(text_body or ""))
    if html_body:
        urls.extend(URL_RE.findall(html_body))
    seen, ordered = set(), []
    for u in urls:
        u = u.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def _brand_lookalike(host: str):
    """Return brand name if host contains it but the registrable domain is not the brand's own."""
    labels = host.split(".")
    registrable_label = labels[-2] if len(labels) >= 2 else host
    for brand in BRANDS:
        if brand in host and registrable_label != brand:
            return brand
    return None


def analyze_url(url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return findings

    def add(sev, title, detail=""):
        findings.append(Finding("url", sev, title, f"{detail} [{url[:120]}]".strip()))

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        add("high", "URL uses raw IP address", host)
    except ValueError:
        pass

    if parsed.scheme == "http":
        add("low", "Unencrypted HTTP link")
    if "@" in parsed.netloc:
        add("high", "URL contains '@' (credential-style obfuscation)")
    if host.startswith("xn--") or ".xn--" in host:
        add("high", "Punycode (possible homograph) domain", host)
    if host in SHORTENERS:
        add("medium", "URL shortener hides destination", host)
    tld = host.rsplit(".", 1)[-1]
    if not is_ip and tld in SUSPICIOUS_TLDS:
        add("medium", "Suspicious TLD", f".{tld}")
    if not is_ip and host.count(".") >= 4:
        add("medium", "Excessive subdomains", host)
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        add("medium", "Non-standard port", str(port))
    if len(url) > 200:
        add("low", "Very long URL")
    if host.count("-") >= 3:
        add("low", "Many hyphens in domain", host)

    brand = None if is_ip else _brand_lookalike(host)
    if brand:
        add("high", f"Possible brand impersonation ({brand})", host)

    path = (parsed.path + "?" + (parsed.query or "")).lower()
    if any(h in path for h in CREDENTIAL_PATH_HINTS) and brand is None and tld in SUSPICIOUS_TLDS:
        add("medium", "Credential-themed path on suspicious domain")
    return findings


def analyze_urls(text_body: str, html_body: str):
    """Return (urls, findings) including anchor-text/href mismatch checks."""
    urls = extract_urls(text_body, html_body)
    findings: List[Finding] = []
    for u in urls:
        findings.extend(analyze_url(u))

    if html_body:
        parser = _LinkParser()
        parser.feed(html_body)
        for href, text in parser.links:
            if not href.lower().startswith(("http://", "https://")):
                continue
            shown = URL_RE.search(text) or re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", text, re.I)
            if not shown:
                continue
            raw = shown.group(0)
            shown_host = urlparse(raw if "://" in raw else "http://" + raw).hostname or ""
            real_host = urlparse(href).hostname or ""
            if shown_host and real_host and shown_host.split(".")[-2:] != real_host.split(".")[-2:]:
                findings.append(Finding(
                    "url", "high", "Link text does not match destination",
                    f"Displayed '{text[:60]}' but links to {real_host}"))
    return urls, findings
