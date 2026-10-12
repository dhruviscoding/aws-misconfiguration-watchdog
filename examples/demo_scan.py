"""Interactive demo script: Simulates an AWS account with misconfigurations using Moto

Run this script to test the full Watchdog scanner, Console reporter,
JSON generator, and Slack integration without needing a live AWS account!

Usage:
    python examples/demo_scan.py
    python examples/demo_scan.py --slack   # (if SLACK_WEBHOOK_URL is set)
"""

import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import boto3
from moto import mock_aws

from watchdog.models import Severity
from watchdog.reporters.console import ConsoleReporter
from watchdog.reporters.json_reporter import JsonReporter
from watchdog.reporters.slack import SlackReporter
from watchdog.runner import WatchdogRunner


def setup_simulated_aws_environment(session: boto3.Session) -> None:
    """Populate in-memory AWS mock with intentional security issues."""
    print("\n[*] Provisioning simulated AWS environment with intentional misconfigurations...")

    # 1. Misconfigured S3 Buckets
    s3 = session.client("s3", region_name="us-east-1")
    # Bucket 1: BPA completely disabled and no encryption
    s3.create_bucket(Bucket="prod-customer-financial-records")

    # Bucket 2: Compliant secure bucket
    s3.create_bucket(Bucket="audit-logs-encrypted-compliant")
    s3.put_public_access_block(
        Bucket="audit-logs-encrypted-compliant",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="audit-logs-encrypted-compliant",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    # 2. Misconfigured IAM User (Console access, no MFA)
    iam = session.client("iam", region_name="us-east-1")
    iam.create_user(UserName="admin-john")
    iam.create_login_profile(UserName="admin-john", Password="Password123!")

    # 3. Misconfigured Security Group (Open SSH 22 to 0.0.0.0/0)
    ec2 = session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="bastion-public-access",
        Description="Public SSH bastion security group",
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # 4. Misconfigured EC2 & EBS (Untagged instance & Unattached EBS volume)
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
    )
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=50,
        VolumeType="gp3",
    )

    print("[*] Simulated AWS environment ready!\n")


def run_demo() -> None:
    # Set mock credentials in environment
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        setup_simulated_aws_environment(session)

        # Execute scan
        runner = WatchdogRunner()
        findings = runner.run_all(session=session, region="us-east-1")

        # 1. Render Console Report
        ConsoleReporter.render(findings)

        # 2. Save JSON Report
        json_path = "findings.json"
        JsonReporter.save(findings, json_path)
        print(f"[+] Structured findings saved to: {os.path.abspath(json_path)}")

        # 3. Test Slack if requested
        if "--slack" in sys.argv:
            webhook = os.getenv("SLACK_WEBHOOK_URL")
            if webhook:
                print(f"[*] Posting findings to Slack webhook ({webhook[:25]}...)...")
                slack = SlackReporter(webhook)
                slack.send(findings, dry_run=False)
            else:
                print("[!] SLACK_WEBHOOK_URL environment variable is not set. Skipping Slack post.")
        else:
            print("[i] To post these results to Slack, set SLACK_WEBHOOK_URL and pass --slack flag.")


if __name__ == "__main__":
    run_demo()
