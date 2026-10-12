"""Unit tests for WatchdogRunner orchestrator."""

from botocore.exceptions import ClientError

from watchdog.checks.base import BaseCheck
from watchdog.models import Finding, Severity
from watchdog.runner import WatchdogRunner


class DummyPassingCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy-passing"

    @property
    def description(self) -> str:
        return "Passing check"

    def run(self, session, region: str) -> list[Finding]:
        _ = (session, region)
        return []


class DummyFailingCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy-failing"

    @property
    def description(self) -> str:
        return "Failing check"

    def run(self, session, region: str) -> list[Finding]:
        _ = session
        return [
            Finding(
                check_name="dummy-failing",
                resource_id="res-123",
                severity=Severity.HIGH,
                explanation="Detected simulated test failure",
                suggested_fix="Remediate test resource",
                region=region,
            )
        ]


class DummyCrashingCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "dummy-crashing"

    @property
    def description(self) -> str:
        return "Crashing check"

    def run(self, session, region: str) -> list[Finding]:
        _ = (session, region)
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "ListObjects")


def test_runner_aggregates_findings(aws_session):
    """Runner should aggregate findings across multiple checks."""
    runner = WatchdogRunner(checks=[DummyPassingCheck(), DummyFailingCheck()])
    findings = runner.run_all(session=aws_session, region="us-east-1")

    assert len(findings) == 1
    assert findings[0].check_name == "dummy-failing"


def test_runner_handles_check_crash_gracefully(aws_session):
    """If one check crashes, runner logs error and continues executing remaining checks."""
    runner = WatchdogRunner(checks=[DummyCrashingCheck(), DummyFailingCheck()])
    findings = runner.run_all(session=aws_session, region="us-east-1")

    assert len(findings) == 1
    assert findings[0].check_name == "dummy-failing"


def test_runner_filters_checks(aws_session):
    """Runner should only execute checks specified in check_filter."""
    runner = WatchdogRunner(checks=[DummyPassingCheck(), DummyFailingCheck()])
    findings = runner.run_all(
        session=aws_session,
        region="us-east-1",
        check_filter=["dummy-passing"],
    )

    assert len(findings) == 0
