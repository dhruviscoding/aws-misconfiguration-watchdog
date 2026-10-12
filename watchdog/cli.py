"""Command-line interface for AWS Misconfiguration Watchdog."""

import argparse
import logging
import sys

import boto3

from watchdog.models import Severity
from watchdog.reporters.console import ConsoleReporter
from watchdog.reporters.json_reporter import JsonReporter
from watchdog.reporters.slack import SlackReporter
from watchdog.runner import WatchdogRunner

logger = logging.getLogger("watchdog")


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="python -m watchdog.cli",
        description="Scan AWS accounts for security misconfigurations and hygiene issues.",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS CLI named profile to use for credentials.",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region to scan (default: us-east-1).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print findings to console without posting to Slack.",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Optional file path to output findings as JSON.",
    )
    parser.add_argument(
        "--checks",
        type=str,
        default=None,
        help="Comma-separated check names to run (e.g., 's3-security,iam-security').",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with status code 1 if any HIGH severity findings are detected.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging output.",
    )
    return parser.parse_args(args)


def main(argv: list[str] | None = None) -> int:
    """Main CLI execution flow."""
    # Attempt UTF-8 reconfiguration on streams if supported
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    args = parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Initialize boto3 Session with profile and region
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as err:
        logger.error("Failed to initialize AWS session: %s", err)
        return 2

    # Parse optional check filter
    check_filter = [c.strip() for c in args.checks.split(",")] if args.checks else None

    # Run checks
    runner = WatchdogRunner()
    findings = runner.run_all(session=session, region=args.region, check_filter=check_filter)

    # 1. Output to Console
    ConsoleReporter.render(findings)

    # 2. Output to JSON file if specified
    if args.output_json:
        JsonReporter.save(findings, args.output_json)

    # 3. Post to Slack (unless dry-run)
    slack = SlackReporter()
    slack.send(findings, dry_run=args.dry_run)

    # Check failure conditions
    if args.fail_on_high:
        has_high = any(f.severity == Severity.HIGH for f in findings)
        if has_high:
            logger.warning("HIGH severity findings detected and --fail-on-high is set.")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
