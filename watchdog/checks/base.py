"""Base interface for all AWS misconfiguration and hygiene checks."""

from abc import ABC, abstractmethod

import boto3

from watchdog.models import Finding


class BaseCheck(ABC):
    """Abstract base class establishing the contract for all security checks.

    Every check module implements this interface, making the watchdog extensible
    and easy to test in isolation.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this check (e.g., 's3-security')."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this check verifies."""

    @abstractmethod
    def run(self, session: boto3.Session, region: str) -> list[Finding]:
        """Execute the check against the given AWS session and region.

        Args:
            session: Configured boto3.Session for AWS API calls.
            region: AWS region string (e.g., 'us-east-1').

        Returns:
            List of detected Finding objects. Returns empty list if all resources comply.
        """
