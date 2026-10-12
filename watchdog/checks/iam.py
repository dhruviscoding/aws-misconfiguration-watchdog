"""IAM Security and Hygiene Check.

Verifies:
1. IAM users with console access have Multi-Factor Authentication (MFA) enabled.
2. Active IAM access keys are not older than 90 days.
3. Policies do not allow unrestricted '*' actions on '*' resources.
"""

import json
import logging
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from watchdog.checks.base import BaseCheck
from watchdog.config import ACCESS_KEY_MAX_AGE_DAYS, BOTO_CONFIG
from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)


class IAMCheck(BaseCheck):
    """Audits IAM users, access keys, and policy definitions."""

    @property
    def name(self) -> str:
        return "iam-security"

    @property
    def description(self) -> str:
        return (
            "Audits IAM users without MFA, access keys older than 90 days, "
            "and overly permissive '*/*' wildcard policies."
        )

    def run(self, session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
        """Execute IAM audit. IAM is a global service; uses us-east-1 endpoint."""
        _ = region  # Satisfies BaseCheck interface; IAM is global
        findings: list[Finding] = []
        iam_client = session.client("iam", region_name="us-east-1", config=BOTO_CONFIG)

        # 1. Audit Users (MFA & Access Keys)
        try:
            paginator = iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    findings.extend(self._check_user_mfa(iam_client, user_name))
                    findings.extend(self._check_access_keys(iam_client, user_name))
                    findings.extend(self._check_inline_policies(iam_client, user_name))
        except ClientError as err:
            logger.error("Failed to list IAM users: %s", err)

        # 2. Audit Customer Managed Policies for wildcard permissions
        findings.extend(self._check_customer_managed_policies(iam_client))

        return findings

    def _check_user_mfa(self, iam_client: Any, user_name: str) -> list[Finding]:
        """Flag users that have console access (login profile) without MFA devices."""
        findings: list[Finding] = []

        # Check if user has console password
        has_console_access = False
        try:
            iam_client.get_login_profile(UserName=user_name)
            has_console_access = True
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code != "NoSuchEntity":
                logger.debug("Error checking login profile for %s: %s", user_name, err)

        # List MFA devices
        try:
            mfa_resp = iam_client.list_mfa_devices(UserName=user_name)
            mfa_devices = mfa_resp.get("MFADevices", [])

            if has_console_access and not mfa_devices:
                findings.append(
                    Finding(
                        check_name="iam-user-no-mfa",
                        resource_id=f"user/{user_name}",
                        severity=Severity.HIGH,
                        explanation=f"IAM user '{user_name}' has console password access enabled without MFA.",
                        suggested_fix=(
                            f"Enforce MFA for user '{user_name}' via AWS Console or attach an MFA-enforcing IAM policy."
                        ),
                        region="global",
                    )
                )
        except ClientError as err:
            logger.warning("Error listing MFA devices for %s: %s", user_name, err)

        return findings

    def _check_access_keys(self, iam_client: Any, user_name: str) -> list[Finding]:
        """Flag active access keys older than threshold (default: 90 days)."""
        findings: list[Finding] = []
        now = datetime.now(UTC)

        try:
            keys_resp = iam_client.list_access_keys(UserName=user_name)
            for key in keys_resp.get("AccessKeyMetadata", []):
                if key.get("Status") != "Active":
                    continue

                create_date = key.get("CreateDate")
                if not create_date:
                    continue

                age_days = (now - create_date).days
                if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                    key_id = key["AccessKeyId"]
                    findings.append(
                        Finding(
                            check_name="iam-old-access-key",
                            resource_id=f"user/{user_name}/key/{key_id}",
                            severity=Severity.MEDIUM,
                            explanation=(
                                f"Access key '{key_id}' for user '{user_name}' is {age_days} days old "
                                f"(exceeds {ACCESS_KEY_MAX_AGE_DAYS} days recommendation)."
                            ),
                            suggested_fix=(
                                f"Rotate access key: create new key, update consumer, then run "
                                f"'aws iam update-access-key --user-name {user_name} --access-key-id {key_id} --status Inactive'."
                            ),
                            region="global",
                        )
                    )
        except ClientError as err:
            logger.warning("Error checking access keys for %s: %s", user_name, err)

        return findings

    def _check_inline_policies(self, iam_client: Any, user_name: str) -> list[Finding]:
        """Inspect inline user policies for wildcard permissions."""
        findings: list[Finding] = []
        try:
            policies_resp = iam_client.list_user_policies(UserName=user_name)
            for policy_name in policies_resp.get("PolicyNames", []):
                policy_doc_resp = iam_client.get_user_policy(
                    UserName=user_name, PolicyName=policy_name
                )
                doc = policy_doc_resp.get("PolicyDocument")
                if isinstance(doc, str):
                    doc = json.loads(urllib.parse.unquote(doc))

                if self._has_admin_wildcard(doc):
                    findings.append(
                        Finding(
                            check_name="iam-admin-wildcard-policy",
                            resource_id=f"user/{user_name}/inline-policy/{policy_name}",
                            severity=Severity.HIGH,
                            explanation=(
                                f"Inline policy '{policy_name}' on user '{user_name}' grants full administrative "
                                "access ('*' actions on '*' resources)."
                            ),
                            suggested_fix=(
                                f"Scope down inline policy '{policy_name}' to specific AWS service actions "
                                "and explicit resource ARNs following least privilege."
                            ),
                            region="global",
                        )
                    )
        except ClientError as err:
            logger.debug("Error checking inline policies for %s: %s", user_name, err)

        return findings

    def _check_customer_managed_policies(self, iam_client: Any) -> list[Finding]:
        """Inspect customer-managed policies (Scope='Local') for wildcard permissions."""
        findings: list[Finding] = []
        try:
            paginator = iam_client.get_paginator("list_policies")
            # Only audit customer-created policies; avoid scanning thousands of AWS-managed policies
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    version_id = policy.get("DefaultVersionId")
                    if not version_id:
                        continue

                    try:
                        version_resp = iam_client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )
                        doc = version_resp.get("PolicyVersion", {}).get("Document")
                        if isinstance(doc, str):
                            doc = json.loads(urllib.parse.unquote(doc))

                        if self._has_admin_wildcard(doc):
                            findings.append(
                                Finding(
                                    check_name="iam-admin-wildcard-policy",
                                    resource_id=policy_arn,
                                    severity=Severity.HIGH,
                                    explanation=(
                                        f"Managed policy '{policy['PolicyName']}' allows unrestricted '*' actions "
                                        "on '*' resources."
                                    ),
                                    suggested_fix=(
                                        f"Restrict policy '{policy['PolicyName']}' by scoping actions to specific "
                                        "APIs and restricting resources to target ARNs."
                                    ),
                                    region="global",
                                )
                            )
                    except ClientError as err:
                        logger.debug("Error retrieving policy version for %s: %s", policy_arn, err)
        except ClientError as err:
            logger.error("Failed to list customer-managed IAM policies: %s", err)

        return findings

    def _has_admin_wildcard(self, policy_doc: dict[str, Any] | None) -> bool:
        """Evaluate if an IAM policy statement grants Action: '*' on Resource: '*' with Effect: Allow."""
        if not policy_doc or not isinstance(policy_doc, dict):
            return False

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_action = "*" in actions
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                return True

        return False
