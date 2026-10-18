"""Orchestrates all detectors for a single email."""
from .attachment_analysis import analyze_attachments
from .content_analysis import analyze_content
from .header_analysis import analyze_headers
from .models import AnalysisResult
from .parser import parse_eml, parse_bytes, ParsedEmail
from .scoring import compute_score
from .url_analysis import analyze_urls


def analyze_parsed(email: ParsedEmail, source: str = "<memory>", use_virustotal: bool = False) -> AnalysisResult:
    result = AnalysisResult(source=source, subject=email.subject, sender=email.from_header)

    result.findings.extend(analyze_headers(email))
    urls, url_findings = analyze_urls(email.text_body, email.html_body)
    result.urls = urls
    result.findings.extend(url_findings)
    result.findings.extend(analyze_content(email.subject, email.text_body, email.html_body))
    result.findings.extend(analyze_attachments(email.attachments))
    result.attachments = [{k: v for k, v in a.items() if k != "head"} for a in email.attachments]

    if use_virustotal:
        from .threat_intel import check_virustotal
        result.findings.extend(check_virustotal(urls, email.attachments))

    return compute_score(result)


def analyze_file(path: str, use_virustotal: bool = False) -> AnalysisResult:
    return analyze_parsed(parse_eml(path), source=path, use_virustotal=use_virustotal)


def analyze_bytes(raw: bytes, source: str = "<bytes>", use_virustotal: bool = False) -> AnalysisResult:
    return analyze_parsed(parse_bytes(raw), source=source, use_virustotal=use_virustotal)
