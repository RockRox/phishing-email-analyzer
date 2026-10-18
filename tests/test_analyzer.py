import os

import pytest

from phishing_analyzer.analyzer import analyze_file, analyze_bytes
from phishing_analyzer.attachment_analysis import analyze_attachments
from phishing_analyzer.content_analysis import analyze_content
from phishing_analyzer.reporting import to_html, to_json, to_text
from phishing_analyzer.url_analysis import analyze_url, analyze_urls, extract_urls

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def titles(findings):
    return [f.title for f in findings]


# ---------- end-to-end ----------
def test_phishing_sample_scores_high():
    r = analyze_file(os.path.join(SAMPLES, "phishing_sample.eml"))
    assert r.score >= 70
    assert "Malicious" in r.verdict
    t = titles(r.findings)
    assert "SPF fail" in t
    assert "DMARC fail" in t
    assert "Reply-To domain differs from From domain" in t
    assert "Link text does not match destination" in t
    assert "URL uses raw IP address" in t
    assert "Executable/script attachment" in t
    assert "Double extension masquerading as document" in t


def test_legit_sample_scores_low():
    r = analyze_file(os.path.join(SAMPLES, "legit_sample.eml"))
    assert r.score < 15
    assert r.verdict == "Likely Benign"


def test_analyze_bytes_minimal():
    raw = b"From: a@b.com\nSubject: hi\n\nhello"
    r = analyze_bytes(raw)
    assert r.subject == "hi"


# ---------- URL ----------
def test_ip_url():
    assert "URL uses raw IP address" in titles(analyze_url("http://10.0.0.1/login"))


def test_shortener():
    assert "URL shortener hides destination" in titles(analyze_url("https://bit.ly/abc"))


def test_punycode():
    assert "Punycode (possible homograph) domain" in titles(analyze_url("https://xn--pypal-4ve.com/"))


def test_brand_impersonation_and_real_brand():
    assert any("brand impersonation" in t for t in titles(analyze_url("https://paypal.secure-login.xyz/")))
    assert not any("brand impersonation" in t for t in titles(analyze_url("https://www.paypal.com/signin")))


def test_extract_urls_dedup():
    urls = extract_urls("see http://a.com/x and http://a.com/x", "")
    assert urls == ["http://a.com/x"]


def test_anchor_mismatch():
    html = '<a href="http://evil.example.net/x">https://bank.example.com</a>'
    _, findings = analyze_urls("", html)
    assert "Link text does not match destination" in titles(findings)


# ---------- content ----------
def test_content_flags():
    f = analyze_content("URGENT ACTION REQUIRED", "Verify your account password immediately or it is suspended", "")
    t = titles(f)
    assert "Urgency / pressure language" in t
    assert "Requests for credentials or sensitive data" in t


def test_benign_content_clean():
    assert analyze_content("Lunch tomorrow?", "Want to grab lunch at noon?", "") == []


def test_password_form():
    f = analyze_content("x", "", '<form action="http://e.example"><input type="password"></form>')
    assert "Embedded password form in email body" in titles(f)


# ---------- attachments ----------
def _att(name, head=b"", size=10):
    return {"filename": name, "sha256": "0" * 64, "size": size, "head": head, "content_type": "x", "md5": ""}


def test_macro_and_archive():
    assert "Macro-enabled Office attachment" in titles(analyze_attachments([_att("a.docm")]))
    assert "Archive attachment (may hide payload)" in titles(analyze_attachments([_att("a.zip")]))


def test_magic_mismatch():
    f = analyze_attachments([_att("report.txt", head=b"MZ\x90\x00")])
    assert "File content is executable but extension is not" in titles(f)


def test_clean_pdf():
    assert analyze_attachments([_att("doc.pdf", head=b"%PDF-1.7")]) == []


# ---------- reporting ----------
@pytest.mark.parametrize("renderer", [to_text, to_json, to_html])
def test_renderers_run(renderer):
    r = analyze_file(os.path.join(SAMPLES, "phishing_sample.eml"))
    out = renderer(r)
    assert "phishing" in out.lower() or "score" in out.lower()


def test_html_escapes():
    raw = b'From: "<script>alert(1)</script>" <a@b.com>\nSubject: <b>x</b>\n\nhi'
    out = to_html(analyze_bytes(raw))
    assert "<script>alert(1)</script>" not in out
