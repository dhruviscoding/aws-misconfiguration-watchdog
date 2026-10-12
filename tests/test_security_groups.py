"""Unit tests for Security Group exposure check using moto."""

from moto import mock_aws

from watchdog.checks.security_groups import SecurityGroupCheck
from watchdog.models import Severity


@mock_aws
def test_compliant_security_group_flags_nothing(aws_session):
    """A security group restricted to private internal CIDRs must produce 0 findings."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="internal-app-sg",
        Description="Internal VPC traffic only",
    )
    sg_id = sg["GroupId"]

    # Inbound allowed only from internal private subnet CIDR
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],  # HTTPS open to web is standard/compliant
            },
        ],
    )

    check = SecurityGroupCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 0


@mock_aws
def test_open_ssh_flags_high(aws_session):
    """A security group exposing port 22 to 0.0.0.0/0 must trigger a HIGH finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="bastion-misconfigured-sg",
        Description="Accidental public SSH",
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = SecurityGroupCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "sg-open-ssh"
    assert sg_id in f.resource_id
    assert f.severity == Severity.HIGH
    assert "exposes SSH (port 22)" in f.explanation


@mock_aws
def test_open_rdp_flags_high(aws_session):
    """A security group exposing port 3389 to 0.0.0.0/0 must trigger a HIGH finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="windows-rdp-sg",
        Description="Public RDP exposure",
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = SecurityGroupCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "sg-open-rdp"
    assert sg_id in f.resource_id
    assert f.severity == Severity.HIGH
    assert "exposes RDP (port 3389)" in f.explanation


@mock_aws
def test_open_all_ports_flags_high(aws_session):
    """A security group allowing all traffic (protocol -1) from 0.0.0.0/0 must trigger a HIGH finding."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="wide-open-sg",
        Description="All ports open to internet",
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = SecurityGroupCheck()
    findings = check.run(aws_session, region="us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "sg-open-all-ports"
    assert sg_id in f.resource_id
    assert f.severity == Severity.HIGH
    assert "on ALL ports" in f.explanation


@mock_aws
def test_port_range_covering_ssh_flags_high(aws_session):
    """A port range such as 20-80 covering port 22 must be caught."""
    ec2 = aws_session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="broad-range-sg",
        Description="Port range 20 to 80 open",
    )
    sg_id = sg["GroupId"]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 20,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = SecurityGroupCheck()
    findings = check.run(aws_session, region="us-east-1")

    ssh_findings = [f for f in findings if f.check_name == "sg-open-ssh"]
    assert len(ssh_findings) == 1
    assert ssh_findings[0].severity == Severity.HIGH
