"""Combine findings into a 0-100 risk score and a verdict."""
from .models import AnalysisResult

# Cap each category so one noisy detector cannot dominate the score.
CATEGORY_CAP = {"header": 40, "url": 40, "content": 35, "attachment": 40, "intel": 40}


def compute_score(result: AnalysisResult) -> AnalysisResult:
    per_cat = {}
    for f in result.findings:
        per_cat[f.category] = per_cat.get(f.category, 0) + f.points
    total = sum(min(v, CATEGORY_CAP.get(k, 30)) for k, v in per_cat.items())
    result.score = min(100, total)

    if result.score >= 70:
        result.verdict = "Malicious / Likely Phishing"
    elif result.score >= 40:
        result.verdict = "Suspicious"
    elif result.score >= 15:
        result.verdict = "Low Risk"
    else:
        result.verdict = "Likely Benign"
    return result
