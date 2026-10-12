"""Unit tests for EC2 and EBS hygiene checks using moto."""

from datetime import UTC, datetime, timedelta

from moto import mock_aws

from watchdog.checks.ec2_hygiene import EC2HygieneCheck
from watchdog.models import Severity


@mock_aws
def test_compliant_instance_and_volume_flags_nothing(aws_session):
    """Running instances with proper tags and attached tagged volumes produce 0 findings."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")

    # Launch instance with required tags
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Owner", "Value": "devsecops@company.com"},
                    {"Key": "Environment", "Value": "production"},
                ],
            },
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Owner", "Value": "devsecops@company.com"},
                    {"Key": "Environment", "Value": "production"},
                ],
            },
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    assert instance_id is not None

    check = EC2HygieneCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 0


@mock_aws
def test_instance_missing_tags_flags_low(aws_session):
    """An instance missing Owner or Environment tags must trigger a LOW severity finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")

    # Launch instance without tags
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    check = EC2HygieneCheck()
    findings = check.run(aws_session, region="us-east-1")

    tag_findings = [
        f for f in findings if f.check_name == "ec2-missing-required-tags" and f.resource_id == instance_id
    ]
    assert len(tag_findings) == 1
    f = tag_findings[0]
    assert f.severity == Severity.LOW
    assert "missing required tags" in f.explanation


@mock_aws
def test_unattached_ebs_volume_flags_medium(aws_session):
    """An unattached EBS volume in 'available' state must trigger a MEDIUM severity finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")

    # Create standalone unattached volume with proper tags
    vol_resp = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=20,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Owner", "Value": "devsecops@company.com"},
                    {"Key": "Environment", "Value": "production"},
                ],
            }
        ],
    )
    volume_id = vol_resp["VolumeId"]

    check = EC2HygieneCheck()
    findings = check.run(aws_session, region="us-east-1")

    unattached_findings = [
        f for f in findings if f.check_name == "ebs-unattached-volume" and f.resource_id == volume_id
    ]
    assert len(unattached_findings) == 1
    f = unattached_findings[0]
    assert f.severity == Severity.MEDIUM
    assert "is unattached ('available')" in f.explanation
    assert "20 GiB gp3" in f.explanation


@mock_aws
def test_stopped_instance_older_than_7_days_flags_medium(aws_session, monkeypatch):
    """An instance stopped for more than 7 days must trigger a MEDIUM severity finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")

    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Owner", "Value": "devsecops@company.com"},
                    {"Key": "Environment", "Value": "production"},
                ],
            },
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Owner", "Value": "devsecops@company.com"},
                    {"Key": "Environment", "Value": "production"},
                ],
            },
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])

    # Mock describe_instances to simulate stopped date > 7 days ago
    orig_describe = ec2.describe_instances

    def mock_describe(*args, **kwargs):
        res = orig_describe(*args, **kwargs)
        past_date = datetime.now(UTC) - timedelta(days=12)
        past_str = past_date.strftime("%Y-%m-%d %H:%M:%S GMT")
        for r in res.get("Reservations", []):
            for inst in r.get("Instances", []):
                if inst.get("InstanceId") == instance_id:
                    inst["StateTransitionReason"] = f"User initiated ({past_str})"
        return res

    monkeypatch.setattr(ec2, "describe_instances", mock_describe)

    orig_client = aws_session.client

    def mock_client(service, *args, **kwargs):
        if service == "ec2":
            return ec2
        return orig_client(service, *args, **kwargs)

    monkeypatch.setattr(aws_session, "client", mock_client)

    check = EC2HygieneCheck()
    findings = check.run(aws_session, region="us-east-1")

    stopped_findings = [
        f for f in findings if f.check_name == "ec2-idle-stopped-instance" and f.resource_id == instance_id
    ]
    assert len(stopped_findings) == 1
    f = stopped_findings[0]
    assert f.severity == Severity.MEDIUM
    assert "has been stopped for" in f.explanation
    assert "incurring idle EBS costs" in f.explanation
