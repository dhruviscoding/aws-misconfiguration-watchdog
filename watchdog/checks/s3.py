"""S3 Security and Hygiene Check.

Verifies:
1. S3 Block Public Access is fully enabled.
2. S3 bucket policies and ACLs do not expose resources to the public.
3. S3 default server-side encryption (SSE) is configured.
"""

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from watchdog.checks.base import BaseCheck
from watchdog.config import BOTO_CONFIG
from watchdog.models import Finding, Severity

logger = logging.getLogger(__name__)

PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class S3Check(BaseCheck):
    """Audits S3 buckets for public exposure risks and missing encryption."""

    @property
    def name(self) -> str:
        return "s3-security"

    @property
    def description(self) -> str:
        return "Scans S3 buckets for public access (BPA, policy, ACL) and missing default encryption."

    def run(self, session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
        """Execute S3 audit against all buckets accessible to session."""
        findings: list[Finding] = []
        s3_client = session.client("s3", region_name=region, config=BOTO_CONFIG)

        try:
            buckets_resp = s3_client.list_buckets()
        except ClientError as err:
            logger.error("Failed to list S3 buckets: %s", err)
            return findings

        buckets = buckets_resp.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            bucket_region = self._get_bucket_region(s3_client, bucket_name, fallback=region)
            regional_s3 = session.client("s3", region_name=bucket_region, config=BOTO_CONFIG)

            # 1. Block Public Access Check
            findings.extend(self._check_public_access_block(regional_s3, bucket_name, bucket_region))

            # 2. Bucket Policy Public Status Check
            findings.extend(self._check_bucket_policy(regional_s3, bucket_name, bucket_region))

            # 3. Bucket ACL Public Grant Check
            findings.extend(self._check_bucket_acl(regional_s3, bucket_name, bucket_region))

            # 4. Default Encryption Check
            findings.extend(self._check_encryption(regional_s3, bucket_name, bucket_region))

        return findings

    def _get_bucket_region(self, s3_client: Any, bucket_name: str, fallback: str) -> str:
        """Resolve the regional endpoint of the bucket to prevent redirection errors."""
        try:
            location_resp = s3_client.get_bucket_location(Bucket=bucket_name)
            loc = location_resp.get("LocationConstraint")
            if not loc:
                return "us-east-1"
            if loc == "EU":
                return "eu-west-1"
            return str(loc)
        except ClientError as err:
            logger.debug("Could not resolve location for bucket %s: %s", bucket_name, err)
            return fallback

    def _check_public_access_block(
        self, s3_client: Any, bucket_name: str, region: str
    ) -> list[Finding]:
        """Ensure all 4 S3 Block Public Access controls are set to True."""
        findings: list[Finding] = []
        try:
            resp = s3_client.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            required_flags = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            missing_or_false = [f for f in required_flags if not config.get(f)]

            if missing_or_false:
                findings.append(
                    Finding(
                        check_name="s3-block-public-access",
                        resource_id=bucket_name,
                        severity=Severity.HIGH,
                        explanation=(
                            f"S3 Block Public Access is disabled or incomplete (missing: {', '.join(missing_or_false)})."
                        ),
                        suggested_fix=(
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        region=region,
                    )
                )
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"):
                findings.append(
                    Finding(
                        check_name="s3-block-public-access",
                        resource_id=bucket_name,
                        severity=Severity.HIGH,
                        explanation="S3 Block Public Access is completely disabled on this bucket.",
                        suggested_fix=(
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        region=region,
                    )
                )
            else:
                logger.warning("Error fetching Public Access Block for %s: %s", bucket_name, err)

        return findings

    def _check_bucket_policy(
        self, s3_client: Any, bucket_name: str, region: str
    ) -> list[Finding]:
        """Check if bucket policy explicitly marks the bucket public."""
        findings: list[Finding] = []
        try:
            resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            is_public = resp.get("PolicyStatus", {}).get("IsPublic", False)
            if is_public:
                findings.append(
                    Finding(
                        check_name="s3-public-policy",
                        resource_id=bucket_name,
                        severity=Severity.HIGH,
                        explanation="S3 bucket policy allows public access to the bucket.",
                        suggested_fix=(
                            f"Update the bucket policy for '{bucket_name}' to remove public principal access ('*' or AWS: '*')."
                        ),
                        region=region,
                    )
                )
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code not in ("NoSuchBucketPolicy", "UnsupportedOperation"):
                logger.debug("Policy status check for %s returned: %s", bucket_name, code)

        return findings

    def _check_bucket_acl(self, s3_client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Detect any ACL grant allowing public access."""
        findings: list[Finding] = []
        try:
            resp = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI")
                if uri in PUBLIC_ACL_URIS:
                    permission = grant.get("Permission", "UNKNOWN")
                    findings.append(
                        Finding(
                            check_name="s3-public-acl",
                            resource_id=bucket_name,
                            severity=Severity.HIGH,
                            explanation=f"S3 ACL grants public '{permission}' access to '{uri.split('/')[-1]}'.",
                            suggested_fix=(
                                f"aws s3api put-bucket-acl --bucket {bucket_name} --acl private"
                            ),
                            region=region,
                        )
                    )
                    break
        except ClientError as err:
            logger.debug("Error checking ACL for %s: %s", bucket_name, err)

        return findings

    def _check_encryption(self, s3_client: Any, bucket_name: str, region: str) -> list[Finding]:
        """Ensure default server-side encryption is active on the bucket."""
        findings: list[Finding] = []
        try:
            resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                findings.append(self._create_encryption_finding(bucket_name, region))
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(self._create_encryption_finding(bucket_name, region))
            else:
                logger.warning("Error fetching encryption for %s: %s", bucket_name, err)

        return findings

    def _create_encryption_finding(self, bucket_name: str, region: str) -> Finding:
        return Finding(
            check_name="s3-unencrypted-bucket",
            resource_id=bucket_name,
            severity=Severity.MEDIUM,
            explanation="Bucket does not have default server-side encryption (SSE) configured.",
            suggested_fix=(
                f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                '--server-side-encryption-configuration \'{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}\''
            ),
            region=region,
        )
