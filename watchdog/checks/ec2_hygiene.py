"""EC2 and EBS Resource Hygiene Check.

Verifies:
1. EC2 instances and EBS volumes have required tags ('Owner', 'Environment').
2. Stopped EC2 instances older than 7 days are flagged to eliminate wasted EBS costs.
3. Unattached EBS volumes ('available' state) are flagged to stop idle storage billing.
"""

import logging
import re
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dateutil import parser as date_parser

from watchdog.checks.base import BaseCheck
from watchdog.config import BOTO_CONFIG, REQUIRED_TAGS, STOPPED_INSTANCE_MAX_AGE_DAYS
from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)

# Regular expression to extract timestamp from EC2 StateTransitionReason
# e.g., "User initiated (2026-10-01 14:22:01 GMT)"
DATE_PATTERN = re.compile(r"\((\d{4}-\d{2}-\d{2}[^)]+)\)")


class EC2HygieneCheck(BaseCheck):
    """Audits EC2 instances and EBS volumes for resource hygiene, cost leaks, and missing tags."""

    @property
    def name(self) -> str:
        return "ec2-ebs-hygiene"

    @property
    def description(self) -> str:
        return (
            "Audits EC2/EBS for missing tags (Owner, Environment), stopped instances > 7 days, "
            "and unattached EBS volumes."
        )

    def run(self, session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
        """Execute EC2 and EBS hygiene audits in the specified region."""
        findings: list[Finding] = []
        ec2_client = session.client("ec2", region_name=region, config=BOTO_CONFIG)

        # 1. Audit EC2 Instances
        try:
            paginator = ec2_client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        findings.extend(self._audit_instance(instance, region))
        except ClientError as err:
            logger.error("Failed to describe EC2 instances in %s: %s", region, err)

        # 2. Audit EBS Volumes
        try:
            vol_paginator = ec2_client.get_paginator("describe_volumes")
            for page in vol_paginator.paginate():
                for volume in page.get("Volumes", []):
                    findings.extend(self._audit_volume(volume, region))
        except ClientError as err:
            logger.error("Failed to describe EBS volumes in %s: %s", region, err)

        return findings

    def _audit_instance(self, instance: dict[str, Any], region: str) -> list[Finding]:
        """Check instance tags and stopped duration."""
        findings: list[Finding] = []
        instance_id = instance.get("InstanceId", "unknown-instance")
        tags = {t.get("Key"): t.get("Value") for t in instance.get("Tags", []) if t.get("Key")}

        # 1. Required Tags Check
        missing_tags = [t for t in REQUIRED_TAGS if not tags.get(t)]
        if missing_tags:
            findings.append(
                Finding(
                    check_name="ec2-missing-required-tags",
                    resource_id=instance_id,
                    severity=Severity.LOW,
                    explanation=(
                        f"EC2 instance '{instance_id}' is missing required tags: {', '.join(missing_tags)}."
                    ),
                    suggested_fix=(
                        f"aws ec2 create-tags --resources {instance_id} "
                        f"--tags Key=Owner,Value=<owner-email> Key=Environment,Value=<env>"
                    ),
                    region=region,
                )
            )

        # 2. Stopped Instance Age Check
        state_name = instance.get("State", {}).get("Name")
        if state_name == "stopped":
            stopped_time = self._extract_stopped_time(instance)
            if stopped_time:
                age_days = (datetime.now(UTC) - stopped_time).days
                if age_days > STOPPED_INSTANCE_MAX_AGE_DAYS:
                    findings.append(
                        Finding(
                            check_name="ec2-idle-stopped-instance",
                            resource_id=instance_id,
                            severity=Severity.MEDIUM,
                            explanation=(
                                f"EC2 instance '{instance_id}' has been stopped for {age_days} days "
                                f"(exceeds {STOPPED_INSTANCE_MAX_AGE_DAYS} days threshold), incurring idle EBS costs."
                            ),
                            suggested_fix=(
                                f"Snapshot root volume if needed and terminate: "
                                f"aws ec2 terminate-instances --instance-ids {instance_id}"
                            ),
                            region=region,
                        )
                    )

        return findings

    def _extract_stopped_time(self, instance: dict[str, Any]) -> datetime | None:
        """Parse timestamp from StateTransitionReason or fallback to LaunchTime."""
        reason = instance.get("StateTransitionReason", "")
        match = DATE_PATTERN.search(reason)
        if match:
            try:
                parsed = date_parser.parse(match.group(1))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                return parsed
            except (ValueError, TypeError):
                pass

        # Fallback if reason string does not contain a parseable date
        launch_time = instance.get("LaunchTime")
        if isinstance(launch_time, datetime):
            if launch_time.tzinfo is None:
                launch_time = launch_time.replace(tzinfo=UTC)
            return launch_time

        return None

    def _audit_volume(self, volume: dict[str, Any], region: str) -> list[Finding]:
        """Check EBS volume tags and unattached status."""
        findings: list[Finding] = []
        vol_id = volume.get("VolumeId", "unknown-volume")
        vol_state = volume.get("State")
        vol_size = volume.get("Size", 0)
        vol_type = volume.get("VolumeType", "gp3")
        attachments = volume.get("Attachments", [])
        tags = {t.get("Key"): t.get("Value") for t in volume.get("Tags", []) if t.get("Key")}

        # 1. Required Tags Check
        missing_tags = [t for t in REQUIRED_TAGS if not tags.get(t)]
        if missing_tags:
            findings.append(
                Finding(
                    check_name="ebs-missing-required-tags",
                    resource_id=vol_id,
                    severity=Severity.LOW,
                    explanation=(
                        f"EBS volume '{vol_id}' is missing required tags: {', '.join(missing_tags)}."
                    ),
                    suggested_fix=(
                        f"aws ec2 create-tags --resources {vol_id} "
                        f"--tags Key=Owner,Value=<owner-email> Key=Environment,Value=<env>"
                    ),
                    region=region,
                )
            )

        # 2. Unattached Volume Check
        if vol_state == "available" or len(attachments) == 0:
            findings.append(
                Finding(
                    check_name="ebs-unattached-volume",
                    resource_id=vol_id,
                    severity=Severity.MEDIUM,
                    explanation=(
                        f"EBS volume '{vol_id}' ({vol_size} GiB {vol_type}) is unattached ('available') "
                        "and generating idle storage costs."
                    ),
                    suggested_fix=(
                        f"Create a final snapshot if needed, then delete: aws ec2 delete-volume --volume-id {vol_id}"
                    ),
                    region=region,
                )
            )

        return findings
