output "cloudfront_domain_name" {
  description = "CloudFront hostname for the site."
  value       = aws_cloudfront_distribution.site.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID. Use this when attaching a CloudFront flat-rate plan."
  value       = aws_cloudfront_distribution.site.id
}

output "domain_name" {
  description = "Custom domain routed to CloudFront."
  value       = var.domain_name
}

output "route53_name_servers" {
  description = "Name servers to delegate the app subdomain from the parent DNS provider."
  value       = aws_route53_zone.site.name_servers
}

output "lambda_function_name" {
  description = "Lambda function serving /api/analyze."
  value       = aws_lambda_function.api.function_name
}

output "lambda_reserved_concurrency" {
  description = "Configured Lambda reserved concurrency cap."
  value       = aws_lambda_function.api.reserved_concurrent_executions
}

output "site_bucket_name" {
  description = "Private S3 bucket used as the static site origin."
  value       = aws_s3_bucket.site.bucket
}
