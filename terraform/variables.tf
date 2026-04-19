variable "aws_region" {
  description = "AWS region for the Lambda function and S3 bucket."
  type        = string
  default     = "us-west-2"
}

variable "name_prefix" {
  description = "Prefix used for named AWS resources."
  type        = string
  default     = "ct-explorer"
}

variable "site_bucket_name" {
  description = "Globally unique S3 bucket name for the static site origin."
  type        = string
}

variable "domain_name" {
  description = "Delegated subdomain for the app, such as ct.example.com. Terraform creates a public hosted zone for this name."
  type        = string
}

variable "lambda_zip_path" {
  description = "Path to a zip file containing the Lambda bootstrap binary."
  type        = string
  default     = "../dist/bootstrap.zip"
}

variable "lambda_memory_mb" {
  description = "Lambda memory size in MB."
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 5
}

variable "lambda_reserved_concurrency" {
  description = "Maximum concurrent Lambda executions. This caps cost but does not keep instances warm."
  type        = number
  default     = 10
}

variable "edge_rate_limit_per_5_minutes" {
  description = "AWS WAF per-IP request limit for the CloudFront distribution over a 5-minute window."
  type        = number
  default     = 1000
}

variable "budget_alert_email" {
  description = "Email address for AWS Budget alerts. Leave empty to skip creating a budget."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  description = "Monthly budget amount in USD when budget_alert_email is set."
  type        = string
  default     = "10"
}

variable "force_destroy_site_bucket" {
  description = "Allow Terraform destroy to delete the static site bucket even when it contains objects."
  type        = bool
  default     = false
}
