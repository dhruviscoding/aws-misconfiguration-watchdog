"""Unit tests for S3 security check using moto."""

from moto import mock_aws

from watchdog.checks.s3 import S3Check
from watchdog.models import Severity


@mock_aws
def test_compliant_bucket_flags_nothing(aws_session):
    """A bucket with Block Public Access and Default Encryption should produce zero findings."""
    s3 = aws_session.client("s3", region_name="us-east-1")
    bucket = "compliant-test-bucket"
    s3.create_bucket(Bucket=bucket)

    # Enable all 4 Block Public Access flags
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enable Default Server-Side Encryption
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    check = S3Check()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 0


@mock_aws
def test_bucket_without_public_access_block_flags_high(aws_session):
    """A bucket with no Public Access Block configured must trigger a HIGH severity finding."""
    s3 = aws_session.client("s3", region_name="us-east-1")
    bucket = "unprotected-bucket"
    s3.create_bucket(Bucket=bucket)

    # Add encryption so only public access is tested
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    check = S3Check()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_name == "s3-block-public-access"
    assert finding.resource_id == bucket
    assert finding.severity == Severity.HIGH
    assert "Block Public Access is completely disabled" in finding.explanation


@mock_aws
def test_bucket_without_encryption_flags_medium(aws_session):
    """A bucket with BPA enabled but no encryption must trigger a MEDIUM severity finding."""
    s3 = aws_session.client("s3", region_name="us-east-1")
    bucket = "unencrypted-bucket"
    s3.create_bucket(Bucket=bucket)

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    check = S3Check()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_name == "s3-unencrypted-bucket"
    assert finding.resource_id == bucket
    assert finding.severity == Severity.MEDIUM
    assert "default server-side encryption" in finding.explanation


@mock_aws
def test_bucket_with_partial_bpa_flags_high(aws_session):
    """A bucket with only some BPA flags enabled must trigger a HIGH severity finding."""
    s3 = aws_session.client("s3", region_name="us-east-1")
    bucket = "partial-bpa-bucket"
    s3.create_bucket(Bucket=bucket)

    # Only 2 out of 4 flags enabled
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    check = S3Check()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_name == "s3-block-public-access"
    assert finding.severity == Severity.HIGH
    assert "IgnorePublicAcls" in finding.explanation
    assert "RestrictPublicBuckets" in finding.explanation
