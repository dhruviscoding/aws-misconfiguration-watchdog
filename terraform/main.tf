terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. GitHub Actions OIDC Identity Provider
# Allows GitHub Actions workflows to authenticate directly via OpenID Connect
# eliminating the need for long-lived, dangerous AWS access keys.
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

# 2. IAM Role Assumed by GitHub Actions via OIDC
# Scoped strictly to the specific GitHub repository and branch to prevent unauthorized repo impersonation.
resource "aws_iam_role" "watchdog_role" {
  name        = var.role_name
  description = "Read-only role assumed by GitHub Actions to run AWS Misconfiguration Watchdog scans."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}"
          }
        }
      }
    ]
  })
}

# 3. Strict Read-Only Policy
# Contains ONLY List*, Get*, and Describe* permissions necessary for inspection.
# ZERO Put, Create, Delete, Update, or Modify actions.
resource "aws_iam_policy" "watchdog_policy" {
  name        = "${var.role_name}-policy"
  description = "Strict least-privilege read-only policy for AWS Misconfiguration Watchdog."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3HygieneAndSecurityInspection"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketPolicyStatus",
          "s3:GetPublicAccessBlock",
          "s3:GetBucketAcl",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMSecurityInspection"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:GetLoginProfile",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListUserPolicies",
          "iam:GetUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2AndSecurityGroupInspection"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4. Attach Policy to Role
resource "aws_iam_role_policy_attachment" "watchdog_attachment" {
  role       = aws_iam_role.watchdog_role.name
  policy_arn = aws_iam_policy.watchdog_policy.arn
}
