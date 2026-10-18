"""Render an AnalysisResult as text, JSON or a standalone HTML report."""
import html
import json
from datetime import datetime, timezone

from .models import AnalysisResult

ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
COLORS = {"high": "#c62828", "medium": "#ef6c00", "low": "#f9a825", "info": "#546e7a"}


def _sorted(result: AnalysisResult):
    return sorted(result.findings, key=lambda f: ORDER.get(f.severity, 9))


def to_text(result: AnalysisResult) -> str:
    lines = [
        "=" * 70,
        "PHISHING EMAIL ANALYSIS REPORT",
        "=" * 70,
        f"File    : {result.source}",
        f"From    : {result.sender}",
        f"Subject : {result.subject}",
        f"Score   : {result.score}/100",
        f"Verdict : {result.verdict}",
        "-" * 70,
        "FINDINGS",
    ]
    if not result.findings:
        lines.append("  (none)")
    for f in _sorted(result):
        lines.append(f"  [{f.severity.upper():6}] ({f.category}) {f.title}")
        if f.detail:
            lines.append(f"           {f.detail}")
    if result.urls:
        lines += ["-" * 70, "URLS"] + [f"  - {u}" for u in result.urls]
    if result.attachments:
        lines += ["-" * 70, "ATTACHMENTS"]
        for a in result.attachments:
            lines.append(f"  - {a['filename']} ({a['size']} bytes)")
            lines.append(f"      sha256: {a['sha256']}")
    lines.append("=" * 70)
    return "\n".join(lines)


def to_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_html(result: AnalysisResult) -> str:
    e = html.escape
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{COLORS.get(f.severity, '#999')}'>{e(f.severity.upper())}</span></td>"
        f"<td>{e(f.category)}</td><td>{e(f.title)}</td><td>{e(f.detail)}</td></tr>"
        for f in _sorted(result)
    )
    urls = "".join(f"<li><code>{e(u)}</code></li>" for u in result.urls) or "<li>None</li>"
    atts = "".join(
        f"<li>{e(a['filename'])} - {a['size']} bytes<br><code>sha256: {e(a['sha256'])}</code></li>"
        for a in result.attachments
    ) or "<li>None</li>"
    gauge = "#c62828" if result.score >= 70 else "#ef6c00" if result.score >= 40 else "#2e7d32"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Phishing Analysis Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:960px;color:#222;padding:0 1rem}}
h1{{margin-bottom:0}} .meta{{color:#666;font-size:.9rem}}
.score{{display:inline-block;padding:.6rem 1.2rem;border-radius:8px;color:#fff;background:{gauge};font-size:1.4rem;font-weight:600}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}} th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top;font-size:.9rem}}
th{{background:#f5f5f5}} .sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}}
code{{background:#f3f3f3;padding:1px 4px;border-radius:3px;word-break:break-all}}
</style></head><body>
<h1>Phishing Email Analysis</h1>
<p class="meta">Generated {now}</p>
<p><b>File:</b> {e(result.source)}<br><b>From:</b> {e(result.sender)}<br><b>Subject:</b> {e(result.subject)}</p>
<p><span class="score">{result.score}/100 - {e(result.verdict)}</span></p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th></tr>{rows or "<tr><td colspan=4>No findings</td></tr>"}</table>
<h2>URLs</h2><ul>{urls}</ul>
<h2>Attachments</h2><ul>{atts}</ul>
</body></html>"""
