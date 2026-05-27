"""
Policy Engine for RepoShield.
Evaluates scan results against user-configured security policies
to produce a PASS / WARN / FAIL verdict.
"""
from models import ScanResult


def evaluate_policy(result: ScanResult, config: dict) -> str:
    """
    Evaluates findings against policy configuration.

    Returns:
        "PASS"  — No actionable findings. Safe to clone.
        "WARN"  — Findings exist but below threshold. User decides.
        "FAIL"  — Findings exceed threshold. Block clone.
    """
    if not result.findings and not result.errors:
        return "PASS"

    # Hard blockers (always FAIL regardless of threshold)
    block_on_secrets = config.get("block_on_secrets", True)
    block_on_critical = config.get("block_on_critical", True)

    if block_on_secrets and any(f.type == "secret" for f in result.findings):
        return "FAIL"

    if block_on_critical and any(f.severity == "CRITICAL" for f in result.findings):
        return "FAIL"

    # Threshold-based decision
    risk_threshold = config.get("risk_threshold", 5.0)

    if result.risk_score >= risk_threshold:
        return "FAIL"

    if result.findings:
        return "WARN"

    return "PASS"
