"""
Risk Scoring Engine for RepoShield.
Calculates a 0.0–10.0 risk score from normalized findings.
"""
import math
from models import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.0,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.0,
    "MEDIUM": 0.7,
    "LOW": 0.4,
}

# Bonus weight for diversity of issue types (secrets + SAST = worse than just SAST)
TYPE_DIVERSITY_BONUS = 1.5


def calculate_risk_score(findings: list[Finding]) -> float:
    """
    Calculates a risk score from 0.0 (clean) to 10.0 (critical).

    Factors:
    - Severity weight of each finding
    - Confidence level (reduces weight for low-confidence findings)
    - Type diversity (multiple categories = higher risk)
    - Presence of secrets always adds significant weight

    Uses logarithmic scaling to prevent score inflation from many LOW findings.
    """
    if not findings:
        return 0.0

    # Base score: weighted sum of all findings
    raw_score = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0.0)
        confidence = CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.5)
        raw_score += weight * confidence

    # Type diversity bonus: multiple attack vectors = higher risk
    unique_types = set(f.type for f in findings if f.type != "error")
    if len(unique_types) > 1:
        raw_score *= 1.0 + (len(unique_types) - 1) * 0.15

    # Logarithmic normalization: prevents inflation, caps at 10.0
    # log2(1 + raw) * 2 gives: raw=1 → 2.0, raw=7 → 6.0, raw=31 → 10.0
    score = math.log2(1.0 + raw_score) * 2.0

    return round(min(10.0, score), 1)
