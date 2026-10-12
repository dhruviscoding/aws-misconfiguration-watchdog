"""Unit tests for Watchdog CLI interface."""

import json
from unittest.mock import patch

from moto import mock_aws

from watchdog.cli import main, parse_args
from watchdog.models import Finding, Severity


def test_cli_argument_parsing():
    """Verify CLI arguments parse flags correctly."""
    args = parse_args(["--profile", "prod", "--region", "eu-west-1", "--dry-run", "--fail-on-high"])
    assert args.profile == "prod"
    assert args.region == "eu-west-1"
    assert args.dry_run is True
    assert args.fail_on_high is True


@mock_aws
def test_cli_dry_run_execution(tmp_path):
    """Running CLI with --dry-run and --output-json writes report and exits 0."""
    json_path = tmp_path / "test_findings.json"

    with patch("watchdog.runner.WatchdogRunner.run_all", return_value=[]):
        exit_code = main(["--dry-run", "--output-json", str(json_path)])

    assert exit_code == 0
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["metadata"]["total_findings"] == 0


@mock_aws
def test_cli_fail_on_high_returns_code_one():
    """When --fail-on-high is set and HIGH findings exist, CLI must exit with status code 1."""
    simulated_findings = [
        Finding(
            check_name="s3-public-access",
            resource_id="bad-bucket",
            severity=Severity.HIGH,
            explanation="Bucket is public",
            suggested_fix="Enable BPA",
            region="us-east-1",
        )
    ]

    with patch("watchdog.runner.WatchdogRunner.run_all", return_value=simulated_findings):
        exit_code = main(["--dry-run", "--fail-on-high"])

    assert exit_code == 1
