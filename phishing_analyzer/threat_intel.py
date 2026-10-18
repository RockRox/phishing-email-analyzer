"""Optional VirusTotal lookups (hashes and URLs). Requires VT_API_KEY env var.

Only hashes and URLs are sent - never the email body or attachment contents.
Uses urllib so the project has zero third-party runtime dependencies.
"""
import base64
import json
import os
import urllib.error
import urllib.request
from typing import List, Dict, Any

from .models import Finding

VT_BASE = "https://www.virustotal.com/api/v3"


def _get(path: str, api_key: str, timeout: int = 15):
    req = urllib.request.Request(f"{VT_BASE}{path}", headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _stats_to_finding(label: str, stats: Dict[str, int]) -> Finding:
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal >= 3:
        return Finding("intel", "high", f"VirusTotal: {label} flagged malicious", f"{mal} malicious, {sus} suspicious")
    if mal >= 1 or sus >= 1:
        return Finding("intel", "medium", f"VirusTotal: {label} flagged", f"{mal} malicious, {sus} suspicious")
    return Finding("intel", "info", f"VirusTotal: {label} clean", "No engines flagged it.")


def check_virustotal(urls: List[str], attachments: List[Dict[str, Any]], max_urls: int = 5) -> List[Finding]:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return [Finding("intel", "info", "VirusTotal skipped", "Set VT_API_KEY to enable threat-intel lookups.")]

    findings: List[Finding] = []
    try:
        for att in attachments:
            data = _get(f"/files/{att['sha256']}", api_key)
            if data:
                stats = data["data"]["attributes"]["last_analysis_stats"]
                findings.append(_stats_to_finding(f"attachment {att['filename']}", stats))
            else:
                findings.append(Finding("intel", "info", f"VirusTotal: {att['filename']} unknown hash"))
        for url in urls[:max_urls]:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            data = _get(f"/urls/{url_id}", api_key)
            if data:
                stats = data["data"]["attributes"]["last_analysis_stats"]
                findings.append(_stats_to_finding(f"URL {url[:60]}", stats))
    except Exception as exc:  # network errors must never crash the analysis
        findings.append(Finding("intel", "info", "VirusTotal lookup failed", str(exc)))
    return findings
