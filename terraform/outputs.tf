output "watchdog_role_arn" {
  description = "ARN of the IAM role assumed by GitHub Actions. Add this to GitHub Repository Secrets as AWS_ROLE_ARN."
  value       = aws_iam_role.watchdog_role.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}
