"""AWS client configuration and retry policies."""

from botocore.config import Config

# Standard exponential backoff retry configuration for AWS API calls.
# Mode 'standard' adheres to AWS best practices with exponential jitter backoff,
# preventing thundering herds and handling transient AWS throttling (e.g., RateExceeded).
BOTO_CONFIG = Config(
    retries={
        "max_attempts": 5,
        "mode": "standard",
    },
    connect_timeout=10,
    read_timeout=30,
)

# Mandatory tags for EC2 / EBS resource hygiene checks
REQUIRED_TAGS = ("Owner", "Environment")

# Access key age threshold in days
ACCESS_KEY_MAX_AGE_DAYS = 90

# Stopped EC2 instance age threshold in days
STOPPED_INSTANCE_MAX_AGE_DAYS = 7
