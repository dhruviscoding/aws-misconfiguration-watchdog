"""Security Group Ingress Exposure Check.

Verifies:
1. Inbound rules do not expose SSH (port 22) to 0.0.0.0/0 or ::/0.
2. Inbound rules do not expose RDP (port 3389) to 0.0.0.0/0 or ::/0.
3. Inbound rules do not expose ALL ports (protocol -1) to 0.0.0.0/0 or ::/0.
"""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from watchdog.checks.base import BaseCheck
from watchdog.config import BOTO_CONFIG
from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)

OPEN_IPV4_CIDR = "0.0.0.0/0"
OPEN_IPV6_CIDR = "::/0"


class SecurityGroupCheck(BaseCheck):
    """Audits EC2 Security Groups for overly permissive inbound internet access."""

    @property
    def name(self) -> str:
        return "security-groups-exposure"

    @property
    def description(self) -> str:
        return (
            "Detects security groups with unrestricted inbound access (0.0.0.0/0 or ::/0) "
            "on SSH (22), RDP (3389), or all ports."
        )

    def run(self, session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
        """Execute Security Group audit across the specified region."""
        findings: list[Finding] = []
        ec2_client = session.client("ec2", region_name=region, config=BOTO_CONFIG)

        try:
            paginator = ec2_client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    findings.extend(self._audit_security_group(sg, region))
        except ClientError as err:
            logger.error("Failed to describe security groups in %s: %s", region, err)

        return findings

    def _audit_security_group(self, sg: dict[str, Any], region: str) -> list[Finding]:
        """Analyze inbound rules (IpPermissions) of a security group."""
        findings: list[Finding] = []
        group_id = sg.get("GroupId", "unknown-sg")
        group_name = sg.get("GroupName", "unnamed")
        target_id = f"{group_id} ({group_name})"

        for rule in sg.get("IpPermissions", []):
            protocol = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            # Check if rule exposes to public internet
            has_public_v4 = any(
                ip_range.get("CidrIp") == OPEN_IPV4_CIDR for ip_range in rule.get("IpRanges", [])
            )
            has_public_v6 = any(
                ip_range.get("CidrIpv6") == OPEN_IPV6_CIDR
                for ip_range in rule.get("Ipv6Ranges", [])
            )

            if not (has_public_v4 or has_public_v6):
                continue

            # 1. Unrestricted All Ports / All Protocols (protocol == '-1')
            if protocol == "-1":
                findings.append(
                    Finding(
                        check_name="sg-open-all-ports",
                        resource_id=target_id,
                        severity=Severity.HIGH,
                        explanation=(
                            f"Security group '{group_name}' ({group_id}) allows unrestricted inbound traffic "
                            "on ALL ports from the public internet."
                        ),
                        suggested_fix=(
                            f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
                            "--protocol -1 --cidr 0.0.0.0/0"
                        ),
                        region=region,
                    )
                )
                continue

            # Check specific ports if TCP/UDP
            if from_port is not None and to_port is not None:
                # 2. SSH (Port 22)
                if from_port <= 22 <= to_port:
                    findings.append(
                        Finding(
                            check_name="sg-open-ssh",
                            resource_id=target_id,
                            severity=Severity.HIGH,
                            explanation=(
                                f"Security group '{group_name}' ({group_id}) exposes SSH (port 22) "
                                "to the public internet."
                            ),
                            suggested_fix=(
                                f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
                                f"--protocol {protocol} --port 22 --cidr 0.0.0.0/0 (use AWS SSM Session Manager instead)."
                            ),
                            region=region,
                        )
                    )

                # 3. RDP (Port 3389)
                if from_port <= 3389 <= to_port:
                    findings.append(
                        Finding(
                            check_name="sg-open-rdp",
                            resource_id=target_id,
                            severity=Severity.HIGH,
                            explanation=(
                                f"Security group '{group_name}' ({group_id}) exposes RDP (port 3389) "
                                "to the public internet."
                            ),
                            suggested_fix=(
                                f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
                                f"--protocol {protocol} --port 3389 --cidr 0.0.0.0/0 (restrict to corporate VPN CIDR)."
                            ),
                            region=region,
                        )
                    )

        return findings
