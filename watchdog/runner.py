"""Watchdog scan orchestrator and check execution engine."""

import logging
from collections.abc import Sequence

import boto3
from botocore.exceptions import ClientError

from watchdog.checks.base import BaseCheck
from watchdog.checks.ec2_hygiene import EC2HygieneCheck
from watchdog.checks.iam import IAMCheck
from watchdog.checks.s3 import S3Check
from watchdog.checks.security_groups import SecurityGroupCheck
from watchdog.models import Finding

logger = logging.getLogger(__name__)

DEFAULT_CHECKS: list[type[BaseCheck]] = [
    S3Check,
    IAMCheck,
    SecurityGroupCheck,
    EC2HygieneCheck,
]


class WatchdogRunner:
    """Coordinates running checks across target AWS accounts and regions."""

    def __init__(
        self,
        checks: Sequence[BaseCheck] | None = None,
    ) -> None:
        """Initialize runner with given checks or standard defaults."""
        if checks is None:
            self.checks = [check_cls() for check_cls in DEFAULT_CHECKS]
        else:
            self.checks = list(checks)

    def run_all(
        self,
        session: boto3.Session,
        region: str = "us-east-1",
        check_filter: Sequence[str] | None = None,
    ) -> list[Finding]:
        """Execute all configured checks and aggregate findings.

        Gracefully isolates individual check failures so an error in one module
        never crashes the remaining scan.

        Args:
            session: Active boto3.Session with read-only AWS permissions.
            region: Primary AWS region to scan.
            check_filter: Optional subset of check names to execute.

        Returns:
            Aggregated list of Finding objects.
        """
        all_findings: list[Finding] = []

        for check in self.checks:
            if check_filter and check.name not in check_filter:
                logger.info("Skipping check '%s' (not in filter)", check.name)
                continue

            logger.info("Running check: %s (%s)", check.name, check.description)
            try:
                findings = check.run(session=session, region=region)
                all_findings.extend(findings)
                logger.info("Check '%s' completed with %d finding(s)", check.name, len(findings))
            except ClientError as err:
                logger.error("AWS ClientError executing check '%s': %s", check.name, err)
            except Exception as err:
                logger.exception("Unexpected exception executing check '%s': %s", check.name, err)

        return all_findings
