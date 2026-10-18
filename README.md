# Phishing Email Analyzer

[!\[CI](https://github.com/RockRox/phishing-email-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/phishing-email-analyzer/actions)
!\[Python](https://img.shields.io/badge/python-3.9%2B-blue)
!\[License](https://img.shields.io/badge/license-MIT-green)

A **static** phishing email analyzer for SOC / blue-team triage. Feed it an `.eml` file and it inspects the
headers, URLs, body content and attachments, then produces an explainable **0-100 risk score** with a verdict
and a report (text, JSON or HTML).

* Zero third-party runtime dependencies (Python standard library only)
* Never executes or saves attachments - only hashes and inspects metadata/magic bytes
* Every score is explained by individual findings, so an analyst can verify the reasoning
* Optional VirusTotal enrichment (hashes and URLs only)

## What it detects

|Area|Checks|
|-|-|
|**Headers**|SPF / DKIM / DMARC results, From vs Reply-To vs Return-Path mismatch, display-name spoofing, missing/odd `Received` chain, bulk mailers|
|**URLs**|raw-IP hosts, `@` obfuscation, punycode/homograph domains, URL shorteners, suspicious TLDs, excessive subdomains, non-standard ports, brand impersonation, **anchor text vs real destination mismatch**|
|**Content**|urgency language, credential/PII requests, financial lures, generic greetings, hidden HTML, embedded password forms / iframes / scripts|
|**Attachments**|executables \& scripts, macro-enabled Office files, archives, double extensions (`invoice.pdf.exe`), magic-byte vs extension mismatch, SHA-256/MD5 for IOC lookup|
|**Threat intel** *(optional)*|VirusTotal reputation for attachment hashes and URLs|

## Quick start

```bash
git clone https://github.com/<your-username>/phishing-email-analyzer.git
cd phishing-email-analyzer

# No install needed:
python -m phishing\_analyzer samples/phishing\_sample.eml

# Or install the CLI command:
pip install .
phishing-analyzer samples/
```

### Usage

```text
phishing-analyzer \[-h] \[-f {text,json,html}] \[-o OUTPUT] \[--vt]
                  \[--fail-score N] \[--version] paths \[paths ...]
```

```bash
# Analyze a whole folder and write HTML reports
phishing-analyzer ./suspicious\_emails -f html -o reports/

# JSON for SIEM / SOAR ingestion
phishing-analyzer mail.eml -f json -o result.json

# Enrich with VirusTotal (Linux/macOS; use $env:VT\_API\_KEY on PowerShell)
export VT\_API\_KEY="your\_key\_here"
phishing-analyzer mail.eml --vt

# Use in a pipeline: exit code 2 if any email scores >= 70
phishing-analyzer ./inbox\_export --fail-score 70
```

> \*\*How to get an `.eml`:\*\* Gmail -> open message -> \*\*Show original / Download original\*\*;
> Outlook -> \*\*File -> Save As -> .eml\*\* (or drag the message to the desktop).

### Use as a library

```python
from phishing\_analyzer.analyzer import analyze\_file
result = analyze\_file("mail.eml")
print(result.score, result.verdict)
for f in result.findings:
    print(f.severity, f.title)
```

## Scoring

Each finding carries a severity (`info`=0, `low`=5, `medium`=15, `high`=30 points). Points are summed per
category, **capped per category** so no single detector dominates, then clamped to 100.

|Score|Verdict|
|-|-|
|70-100|Malicious / Likely Phishing|
|40-69|Suspicious|
|15-39|Low Risk|
|0-14|Likely Benign|

## Project structure

```text
phishing-email-analyzer/
├── phishing\_analyzer/
│   ├── parser.py               # .eml -> ParsedEmail (bodies, attachments, hashes)
│   ├── header\_analysis.py      # SPF/DKIM/DMARC + sender spoofing checks
│   ├── url\_analysis.py         # URL extraction + heuristics
│   ├── content\_analysis.py     # social-engineering language / HTML tricks
│   ├── attachment\_analysis.py  # extension, double-ext, magic-byte checks
│   ├── threat\_intel.py         # optional VirusTotal enrichment
│   ├── scoring.py              # risk score + verdict
│   ├── reporting.py            # text / JSON / HTML renderers
│   ├── analyzer.py             # orchestration
│   └── cli.py                  # command-line interface
├── samples/                    # synthetic phishing + legitimate emails
├── tests/                      # pytest suite
├── .github/workflows/ci.yml    # CI on Python 3.9-3.12
├── pyproject.toml
└── requirements.txt
```

## Testing

```bash
pip install -r requirements.txt
python -m pytest -v
```

## Limitations (be honest about these in interviews)

* **Heuristic, not a verdict.** Treat the score as triage support; confirm in a sandbox / with the user.
* SPF/DKIM/DMARC are read from the `Authentication-Results` / `Received-SPF` headers added by the receiving
server - the tool does not re-run DNS lookups or cryptographic DKIM verification.
* Registrable-domain detection is a simplified heuristic (no Public Suffix List).
* No sandbox detonation, QR-code (quishing) decoding, or OCR of image-only emails.
* Sample emails use reserved example domains / documentation IPs and contain no working malware.

## Roadmap ideas

* DNS-based SPF/DMARC verification (`dnspython`) and real DKIM signature validation
* Public Suffix List support, WHOIS domain-age checks
* QR-code and image OCR extraction
* Flask/React web UI for drag-and-drop analysis
* Export IOCs as STIX 2.1 / MISP events; MITRE ATT\&CK mapping (T1566.001 / .002)
* Splunk / Elastic-friendly JSON schema

## Responsible use

For defensive analysis of emails you are authorised to examine. Do not open links or attachments from
suspicious messages outside an isolated environment.

## License

MIT - see [LICENSE](LICENSE).

