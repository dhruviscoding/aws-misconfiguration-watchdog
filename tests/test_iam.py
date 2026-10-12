"""Unit tests for IAM security check using moto."""

import json
from datetime import UTC, datetime, timedelta

from moto import mock_aws

from watchdog.checks.iam import IAMCheck
from watchdog.models import Severity


@mock_aws
def test_compliant_user_and_policy_flags_nothing(aws_session):
    """An IAM user with MFA, a fresh access key, and a scoped policy must produce 0 findings."""
    iam = aws_session.client("iam", region_name="us-east-1")

    # 1. Create compliant user
    user_name = "compliant-alice"
    iam.create_user(UserName=user_name)
    iam.create_login_profile(UserName=user_name, Password="StrongPassword123!")

    # Enable MFA
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=mfa["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    # Fresh access key
    iam.create_access_key(UserName=user_name)

    # Scoped customer managed policy
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-secure-bucket/*",
            }
        ],
    }
    iam.create_policy(
        PolicyName="ScopedS3Access",
        PolicyDocument=json.dumps(scoped_policy),
    )

    check = IAMCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 0


@mock_aws
def test_user_without_mfa_flags_high(aws_session):
    """An IAM user with a console login profile but no MFA device must trigger a HIGH severity finding."""
    iam = aws_session.client("iam", region_name="us-east-1")
    user_name = "insecure-bob"
    iam.create_user(UserName=user_name)
    iam.create_login_profile(UserName=user_name, Password="TemporaryPassword123!")

    check = IAMCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_name == "iam-user-no-mfa"
    assert finding.resource_id == f"user/{user_name}"
    assert finding.severity == Severity.HIGH
    assert "without MFA" in finding.explanation


@mock_aws
def test_old_access_key_flags_medium(aws_session, monkeypatch):
    """An access key older than 90 days must trigger a MEDIUM severity finding."""
    iam = aws_session.client("iam", region_name="us-east-1")
    user_name = "developer-carol"
    iam.create_user(UserName=user_name)
    key_resp = iam.create_access_key(UserName=user_name)
    key_id = key_resp["AccessKey"]["AccessKeyId"]

    orig_list_keys = iam.list_access_keys

    def mock_list_access_keys(*args, **kwargs):
        res = orig_list_keys(*args, **kwargs)
        for k in res.get("AccessKeyMetadata", []):
            k["CreateDate"] = datetime.now(UTC) - timedelta(days=100)
        return res

    monkeypatch.setattr(iam, "list_access_keys", mock_list_access_keys)

    orig_client = aws_session.client

    def mock_client(service, *args, **kwargs):
        if service == "iam":
            return iam
        return orig_client(service, *args, **kwargs)

    monkeypatch.setattr(aws_session, "client", mock_client)

    check = IAMCheck()
    findings = check.run(aws_session, region="us-east-1")

    old_key_findings = [f for f in findings if f.check_name == "iam-old-access-key"]
    assert len(old_key_findings) == 1
    f = old_key_findings[0]
    assert f.severity == Severity.MEDIUM
    assert key_id in f.resource_id
    assert "exceeds 90 days recommendation" in f.explanation


@mock_aws
def test_wildcard_policy_flags_high(aws_session):
    """A customer-managed policy with Action: * and Resource: * must trigger a HIGH severity finding."""
    iam = aws_session.client("iam", region_name="us-east-1")

    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    resp = iam.create_policy(
        PolicyName="OverlyPermissiveAdmin",
        PolicyDocument=json.dumps(admin_policy),
    )
    policy_arn = resp["Policy"]["Arn"]

    check = IAMCheck()
    findings = check.run(aws_session, region="us-east-1")

    wildcard_findings = [f for f in findings if f.check_name == "iam-admin-wildcard-policy"]
    assert len(wildcard_findings) == 1
    f = wildcard_findings[0]
    assert f.severity == Severity.HIGH
    assert f.resource_id == policy_arn
    assert "unrestricted '*'" in f.explanation
