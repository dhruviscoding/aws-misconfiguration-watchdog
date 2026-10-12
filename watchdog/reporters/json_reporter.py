"""JSON report generator for machine readability and CI artifact storage."""

import json
import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)


class JsonReporter:
    """Serializes findings to structured JSON format."""

    @staticmethod
    def generate_payload(findings: list[Finding]) -> dict:
        """Create structured dictionary with scan metadata and findings."""
        counts = Counter(f.severity.value for f in findings)
        return {
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "total_findings": len(findings),
                "summary": {
                    "high": counts.get(Severity.HIGH.value, 0),
                    "medium": counts.get(Severity.MEDIUM.value, 0),
                    "low": counts.get(Severity.LOW.value, 0),
                },
            },
            "findings": [f.to_dict() for f in findings],
        }

    @classmethod
    def save(cls, findings: list[Finding], output_path: str | Path) -> Path:
        """Save JSON report to the specified file path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = cls.generate_payload(findings)

        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        logger.info("JSON report saved to %s", path.resolve())
        return path
