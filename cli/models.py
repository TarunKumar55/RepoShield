"""
Unified data models for RepoShield scanner findings.
All scanner outputs are normalized into these models before scoring/display.
"""
import hashlib
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single normalized security finding from any scanner."""
    id: str = ""
    tool: str                       # "gitleaks", "semgrep", "bandit", "scanner"
    type: str                       # "secret", "sast", "error", "dependency", "anomaly"
    category: str                   # Human display: "Secret", "SAST", "Python SAST"
    severity: str                   # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    confidence: str = "HIGH"        # "HIGH", "MEDIUM", "LOW"
    file: str = ""
    line: Optional[int] = None
    title: str
    detail: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None

    def model_post_init(self, __context):
        if not self.id:
            raw = f"{self.tool}:{self.type}:{self.file}:{self.line}:{self.title}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]


class ScanResult(BaseModel):
    """Complete result of a security scan, including all normalized findings."""
    repo_url: str
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_duration_seconds: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "PASS"           # "PASS", "WARN", "FAIL"
    raw_findings: dict = Field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0 and len(self.errors) == 0

    @property
    def summary(self) -> str:
        if self.errors and not self.findings:
            return "; ".join(self.errors)
        if not self.findings:
            return "No issues found"
        counts = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        parts = [f"{count} {cat}" for cat, count in counts.items()]
        return f"Found {', '.join(parts)}."
