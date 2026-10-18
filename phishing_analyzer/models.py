"""Shared data structures."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30}


@dataclass
class Finding:
    """A single suspicious (or informational) observation."""
    category: str        # header | url | content | attachment | intel
    severity: str        # info | low | medium | high
    title: str
    detail: str = ""

    @property
    def points(self) -> int:
        return SEVERITY_POINTS.get(self.severity, 0)


@dataclass
class AnalysisResult:
    source: str
    subject: str = ""
    sender: str = ""
    findings: List[Finding] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    verdict: str = "Unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
