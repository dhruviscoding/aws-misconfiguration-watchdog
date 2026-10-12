"""Console reporter for terminal output."""

import sys
from collections import Counter

from watchdog.models import Finding, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"


def _safe_print(text: str, stream=sys.stdout) -> None:
    """Safely print text handling Windows consoles that don't support full UTF-8 emojis."""
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        # Fallback replacing emojis with ASCII equivalents
        ascii_text = (
            text.replace("🔴", "[HIGH]")
            .replace("🟡", "[MED]")
            .replace("🔵", "[LOW]")
            .replace("✅", "[OK]")
            .replace("🛡️", "[*]")
            .replace("—", "-")
        )
        print(ascii_text.encode("ascii", "replace").decode("ascii"), file=stream)


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

        _safe_print(f"\n{BOLD}{'=' * 78}{RESET}", stream=stream)
        _safe_print(f"{BOLD}  AWS MISCONFIGURATION WATCHDOG - SECURITY & HYGIENE REPORT{RESET}", stream=stream)
        _safe_print(f"{BOLD}{'=' * 78}{RESET}\n", stream=stream)

        # Summary Badges
        _safe_print(
            f"  {Severity.HIGH.color}{Severity.HIGH.emoji} HIGH: {high}{RESET}  |  "
            f"{Severity.MEDIUM.color}{Severity.MEDIUM.emoji} MEDIUM: {medium}{RESET}  |  "
            f"{Severity.LOW.color}{Severity.LOW.emoji} LOW: {low}{RESET}  |  "
            f"{BOLD}TOTAL: {total}{RESET}\n",
            stream=stream,
        )

        if total == 0:
            _safe_print(
                f"  {GREEN}✅ All clear! No security misconfigurations or hygiene issues detected.{RESET}\n",
                stream=stream,
            )
            _safe_print(f"{BOLD}{'-' * 78}{RESET}\n", stream=stream)
            return

        # Sort findings by severity priority: HIGH first, then MEDIUM, then LOW
        priority = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        sorted_findings = sorted(findings, key=lambda f: priority[f.severity])

        for idx, finding in enumerate(sorted_findings, start=1):
            sev_badge = f"{finding.severity.color}{BOLD}[{finding.severity.value}]{RESET}"
            _safe_print(
                f"  {idx}. {sev_badge} {BOLD}{finding.check_name}{RESET} ({finding.region})",
                stream=stream,
            )
            _safe_print(f"     Resource: {finding.resource_id}", stream=stream)
            _safe_print(f"     Issue:    {finding.explanation}", stream=stream)
            _safe_print(f"     Fix:      {finding.suggested_fix}", stream=stream)
            _safe_print("", stream=stream)

        _safe_print(f"{BOLD}{'=' * 78}{RESET}\n", stream=stream)
