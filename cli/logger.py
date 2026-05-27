"""
Structured Logging for RepoShield.
Writes JSON-formatted scan events to ~/.reposhield/logs/ for observability,
debugging, and future analytics.

Each scan gets a unique run_id. Log entries are appended to a daily log file.
"""
import os
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path


def get_log_dir() -> Path:
    """Returns the log directory, creating it if needed."""
    log_dir = Path(os.path.expanduser("~")) / ".reposhield" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def generate_run_id() -> str:
    """Generates a unique run ID for this scan session."""
    return uuid.uuid4().hex[:12]


class ScanLogger:
    """
    Structured logger that writes JSON events to a daily log file.
    
    Usage:
        logger = ScanLogger()
        logger.log_event("scan_start", repo_url="https://github.com/user/repo")
        ...
        logger.log_scan_complete(result)
    """

    def __init__(self):
        self.run_id = generate_run_id()
        self.start_time = datetime.now()
        self._log_dir = get_log_dir()
        self._log_file = self._log_dir / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

    def _write(self, entry: dict):
        """Append a JSON line to the daily log file."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            # Logging should never crash the tool
            pass

    def log_event(self, event: str, **kwargs):
        """Log a generic event with optional key-value data."""
        entry = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "event": event,
        }
        entry.update(kwargs)
        self._write(entry)

    def log_scan_start(self, repo_url: str, auto_mode: bool = False, output_format: str = "table"):
        """Log the start of a scan."""
        self.log_event(
            "scan_start",
            repo_url=repo_url,
            auto_mode=auto_mode,
            output_format=output_format,
        )

    def log_scan_complete(self, result):
        """Log scan completion with full result summary."""
        elapsed = (datetime.now() - self.start_time).total_seconds()

        # Count findings by category
        category_counts = {}
        severity_counts = {}
        for f in result.findings:
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        self.log_event(
            "scan_complete",
            repo_url=result.repo_url,
            duration_seconds=round(elapsed, 2),
            scan_duration_seconds=result.scan_duration_seconds,
            finding_count=len(result.findings),
            error_count=len(result.errors),
            risk_score=result.risk_score,
            verdict=result.verdict,
            categories=category_counts,
            severities=severity_counts,
        )

    def log_verdict(self, verdict: str, action: str):
        """Log the final action taken (cloned, blocked, aborted)."""
        self.log_event(
            "verdict_action",
            verdict=verdict,
            action=action,
        )

    def log_error(self, error: str, context: str = ""):
        """Log an error event."""
        self.log_event(
            "error",
            error=error,
            context=context,
        )
