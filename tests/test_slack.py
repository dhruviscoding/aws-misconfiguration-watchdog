"""Unit tests for Slack Block Kit reporter."""

from unittest.mock import MagicMock

import requests

from watchdog.models import Finding, Severity
from watchdog.reporters.slack import SlackReporter


def test_slack_payload_all_clear_when_zero_findings():
    """When zero findings exist, Block Kit message displays an all-clear confirmation."""
    reporter = SlackReporter(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    payload = reporter.build_payload([])

    blocks = payload["blocks"]
    assert len(blocks) == 3
    assert blocks[0]["type"] == "header"
    assert "All clear!" in blocks[2]["text"]["text"]


def test_slack_payload_includes_findings_breakdown():
    """When findings exist, payload includes summary counts and top finding blocks."""
    findings = [
        Finding(
            check_name="s3-public-access",
            resource_id="my-bucket",
            severity=Severity.HIGH,
            explanation="Bucket is public",
            suggested_fix="Enable BPA",
            region="us-east-1",
        ),
        Finding(
            check_name="ec2-missing-required-tags",
            resource_id="i-12345",
            severity=Severity.LOW,
            explanation="Missing Owner tag",
            suggested_fix="Tag instance",
            region="us-east-1",
        ),
    ]

    reporter = SlackReporter(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    payload = reporter.build_payload(findings)

    blocks = payload["blocks"]
    summary_text = blocks[1]["text"]["text"]
    assert "*HIGH:* `1`" in summary_text
    assert "*LOW:* `1`" in summary_text
    assert "*Total Issues:* `2`" in summary_text

    # Top finding check
    item_block = blocks[3]
    assert "s3-public-access" in item_block["text"]["text"]
    assert "my-bucket" in item_block["text"]["text"]


def test_slack_dry_run_skips_network_call(monkeypatch):
    """Dry run mode must not send any HTTP requests."""
    mock_post = MagicMock()
    monkeypatch.setattr(requests, "post", mock_post)

    reporter = SlackReporter(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    success = reporter.send([], dry_run=True)

    assert success is True
    mock_post.assert_not_called()


def test_slack_send_successful(monkeypatch):
    """Successful HTTP 200 response returns True."""
    mock_response = MagicMock(status_code=200)
    mock_post = MagicMock(return_value=mock_response)
    monkeypatch.setattr(requests, "post", mock_post)

    reporter = SlackReporter(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    success = reporter.send([])

    assert success is True
    mock_post.assert_called_once()


def test_slack_send_fails_on_network_error(monkeypatch):
    """Connection errors should be handled cleanly without raising an unhandled exception."""
    mock_post = MagicMock(side_effect=requests.RequestException("Connection timed out"))
    monkeypatch.setattr(requests, "post", mock_post)

    reporter = SlackReporter(webhook_url="https://hooks.slack.com/services/T00/B00/X00")
    success = reporter.send([])

    assert success is False
