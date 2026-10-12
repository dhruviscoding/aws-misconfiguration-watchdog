"""Data models for security findings and severities."""

from dataclasses import asdict, dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for misconfiguration findings."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def color(self) -> str:
        """ANSI color escape code for terminal rendering."""
        match self:
            case Severity.HIGH:
                return "\033[91m"  # Bright Red
            case Severity.MEDIUM:
                return "\033[93m"  # Bright Yellow
            case Severity.LOW:
                return "\033[94m"  # Bright Blue

    @property
    def emoji(self) -> str:
        """Slack / Markdown emoji representing severity."""
        match self:
            case Severity.HIGH:
                return "🔴"
            case Severity.MEDIUM:
                return "🟡"
            case Severity.LOW:
                return "🔵"


@dataclass(frozen=True)
class Finding:
    """Represents a single AWS misconfiguration or hygiene issue.

    Attributes:
        check_name: Machine-readable identifier for the check (e.g. 's3-public-access').
        resource_id: Identifier or ARN of the misconfigured AWS resource.
        severity: HIGH, MEDIUM, or LOW severity level.
        explanation: Concise one-line explanation of the detected problem.
        suggested_fix: Practical remediation action to resolve the issue.
        region: AWS region where the resource resides (or 'global').
    """

    check_name: str
    resource_id: str
    severity: Severity
    explanation: str
    suggested_fix: str
    region: str = "global"

    def to_dict(self) -> dict[str, str]:
        """Convert finding to serializable dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
