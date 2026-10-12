variable "aws_region" {
  description = "AWS region for provider configuration"
  type        = string
  default     = "us-east-1"
}

variable "github_org" {
  description = "GitHub username or organization owning the repository"
  type        = string
  default     = "YOUR_GITHUB_USERNAME"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "aws-misconfiguration-watchdog"
}

variable "github_branch" {
  description = "Target Git branch allowed to assume the scanning role (default: main)"
  type        = string
  default     = "main"
}

variable "role_name" {
  description = "Name of the IAM read-only role assumed by GitHub Actions"
  type        = string
  default     = "github-actions-watchdog-read-only"
}
