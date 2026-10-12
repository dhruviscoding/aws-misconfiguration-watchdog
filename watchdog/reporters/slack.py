"""Slack Block Kit report generator and webhook sender."""

import logging
import os
from collections import Counter
from typing import Any

import requests

from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)

ENV_WEBHOOK_KEY = "SLACK_WEBHOOK_URL"
MAX_TOP_FINDINGS = 10


class SlackReporter:
    """Formats findings using Slack Block Kit and posts to Incoming Webhook."""

    def __init__(self, webhook_url: str | None = None) -> None:
        """Initialize with explicit webhook or fallback to SLACK_WEBHOOK_URL environment variable."""
        self.webhook_url = webhook_url or os.getenv(ENV_WEBHOOK_KEY)

    def build_payload(self, findings: list[Finding]) -> dict[str, Any]:
        """Construct Slack Block Kit message payload."""
        counts = Counter(f.severity for f in findings)
        high = counts[Severity.HIGH]
        medium = counts[Severity.MEDIUM]
        low = counts[Severity.LOW]
        total = len(findings)

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ AWS Misconfiguration Watchdog Report",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Scan Summary:*\n"
                        f"🔴 *HIGH:* `{high}`   "
                        f"🟡 *MEDIUM:* `{medium}`   "
                        f"🔵 *LOW:* `{low}`   "
                        f"|   *Total Issues:* `{total}`"
                    ),
                },
            },
        ]

        # Case 1: All clear!
        if total == 0:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "✅ *All clear!* No security misconfigurations or hygiene issues detected in this scan.",
                    },
                }
            )
            return {"blocks": blocks}

        # Case 2: Findings detected -> list top findings
        blocks.append({"type": "divider"})

        priority = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        sorted_findings = sorted(findings, key=lambda f: priority[f.severity])
        displayed_findings = sorted_findings[:MAX_TOP_FINDINGS]

        for idx, finding in enumerate(displayed_findings, start=1):
            text = (
                f"{finding.severity.emoji} *#{idx} [{finding.severity.value}] {finding.check_name}*\n"
                f"• *Resource:* `{finding.resource_id}` ({finding.region})\n"
                f"• *Issue:* {finding.explanation}\n"
                f"• *Suggested Fix:* `{finding.suggested_fix}`"
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text},
                }
            )

        if total > MAX_TOP_FINDINGS:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"_... and {total - MAX_TOP_FINDINGS} more findings. "
                                "Download the complete JSON report from the GitHub Actions run artifacts._"
                            ),
                        }
                    ],
                }
            )

        return {"blocks": blocks}

    def send(self, findings: list[Finding], dry_run: bool = False) -> bool:
        """Deliver report to Slack or skip if in dry-run mode."""
        payload = self.build_payload(findings)

        if dry_run:
            logger.info("Dry-run active: Slack notification skipped.")
            return True

        if not self.webhook_url:
            logger.warning(
                "No Slack webhook configured (missing %s environment variable). "
                "Skipping Slack delivery.",
                ENV_WEBHOOK_KEY,
            )
            return False

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("Successfully posted watchdog findings to Slack.")
                return True
            logger.error("Slack returned non-200 status code %d: %s", resp.status_code, resp.text)
            return False
        except requests.RequestException as err:
            logger.error("Failed to post message to Slack webhook: %s", err)
            return False
