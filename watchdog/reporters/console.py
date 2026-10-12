"""Console reporter for terminal output."""

import sys
from collections import Counter

from watchdog.models import Finding, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"


class ConsoleReporter:
    """Formats and prints findings cleanly to standard output."""

    @staticmethod
    def render(findings: list[Finding], stream=sys.stdout) -> None:
        """Render formatted findings to the specified stream."""
        counts = Counter(f.severity for f in findings)
        high = counts[Severity.HIGH]
        medium = counts[Severity.MEDIUM]
        low = counts[Severity.LOW]
        total = len(findings)

        print(f"\n{BOLD}{'=' * 78}{RESET}", file=stream)
        print(f"{BOLD}  AWS MISCONFIGURATION WATCHDOG — SECURITY & HYGIENE REPORT{RESET}", file=stream)
        print(f"{BOLD}{'=' * 78}{RESET}\n", file=stream)

        # Summary Badges
        print(
            f"  {Severity.HIGH.color}{Severity.HIGH.emoji} HIGH: {high}{RESET}  |  "
            f"{Severity.MEDIUM.color}{Severity.MEDIUM.emoji} MEDIUM: {medium}{RESET}  |  "
            f"{Severity.LOW.color}{Severity.LOW.emoji} LOW: {low}{RESET}  |  "
            f"{BOLD}TOTAL: {total}{RESET}\n",
            file=stream,
        )

        if total == 0:
            print(
                f"  {GREEN}✅ All clear! No security misconfigurations or hygiene issues detected.{RESET}\n",
                file=stream,
            )
            print(f"{BOLD}{'-' * 78}{RESET}\n", file=stream)
            return

        # Sort findings by severity priority: HIGH first, then MEDIUM, then LOW
        priority = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        sorted_findings = sorted(findings, key=lambda f: priority[f.severity])

        for idx, finding in enumerate(sorted_findings, start=1):
            sev_badge = f"{finding.severity.color}{BOLD}[{finding.severity.value}]{RESET}"
            print(
                f"  {idx}. {sev_badge} {BOLD}{finding.check_name}{RESET} "
                f"({finding.region})",
                file=stream,
            )
            print(f"     Resource: {finding.resource_id}", file=stream)
            print(f"     Issue:    {finding.explanation}", file=stream)
            print(f"     Fix:      {finding.suggested_fix}", file=stream)
            print(file=stream)

        print(f"{BOLD}{'=' * 78}{RESET}\n", file=stream)
