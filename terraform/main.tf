data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

locals {
  s3_origin_id     = "static-site"
  lambda_origin_id = "lambda-api"

  cloudfront_managed_cache_policy_caching_optimized        = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  cloudfront_managed_cache_policy_caching_disabled         = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  cloudfront_managed_origin_request_all_viewer_except_host = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

  # CloudFront origins need only the Function URL hostname, not the scheme.
  lambda_function_url_domain = trimsuffix(
    trimprefix(aws_lambda_function_url.api.function_url, "https://"),
    "/"
  )
}

# This hosted zone is for the delegated app subdomain, such as
# ct.jordan-wright.com. Delegate it from the parent DNS provider with an NS
# record that points at this zone's name servers.
resource "aws_route53_zone" "site" {
  name = var.domain_name
}

# The function does not need app data-plane AWS API access. Its only attached
# policy is for writing execution logs to CloudWatch.
resource "aws_iam_role" "lambda" {
  name               = "${var.name_prefix}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Keep this function outside a VPC. It needs outbound internet access for public
# HTTPS hosts and CT logs, and avoiding a VPC also avoids NAT gateway cost.
resource "aws_lambda_function" "api" {
  function_name                  = "${var.name_prefix}-api"
  role                           = aws_iam_role.lambda.arn
  architectures                  = ["arm64"]
  filename                       = var.lambda_zip_path
  handler                        = "bootstrap"
  memory_size                    = var.lambda_memory_mb
  package_type                   = "Zip"
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  runtime                        = "provided.al2023"
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  timeout                        = var.lambda_timeout_seconds
}

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "AWS_IAM"
}

# Static files stay private. CloudFront is the only intended public reader.
resource "aws_s3_bucket" "site" {
  bucket        = var.site_bucket_name
  force_destroy = var.force_destroy_site_bucket
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.name_prefix}-site-oac"
  description                       = "Allow CloudFront to read the private static site bucket."
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_origin_access_control" "lambda" {
  name                              = "${var.name_prefix}-lambda-oac"
  description                       = "Allow CloudFront to invoke the Lambda Function URL."
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# WAFv2 web ACLs attached to CloudFront are managed through the us-east-1 API.
# Keep this rule simple for CloudFront flat-rate tier compatibility.
resource "aws_wafv2_web_acl" "edge" {
  region = "us-east-1"

  name  = "${var.name_prefix}-edge"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-by-ip"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.edge_rate_limit_per_5_minutes
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-edge-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-edge"
    sampled_requests_enabled   = true
  }
}

# CloudFront requires ACM certificates in us-east-1, even when the app's
# regional resources live elsewhere.
resource "aws_acm_certificate" "site" {
  region = "us-east-1"

  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# DNS validation records live inside the delegated subdomain hosted zone. ACM
# validation will complete after the parent DNS provider delegates the subdomain
# to the Route53 name servers from the route53_name_servers output.
resource "aws_route53_record" "certificate_validation" {
  for_each = {
    for option in aws_acm_certificate.site.domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.site.zone_id
}

resource "aws_acm_certificate_validation" "site" {
  region = "us-east-1"

  certificate_arn         = aws_acm_certificate.site.arn
  validation_record_fqdns = [for record in aws_route53_record.certificate_validation : record.fqdn]
}

# Route all static paths to S3 and only /api/* to the Lambda Function URL.
resource "aws_cloudfront_distribution" "site" {
  aliases             = [var.domain_name]
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.name_prefix} static site and API"
  web_acl_id          = aws_wafv2_web_acl.edge.arn

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = local.s3_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  origin {
    domain_name              = local.lambda_function_url_domain
    origin_id                = local.lambda_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.lambda.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = local.s3_origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = local.cloudfront_managed_cache_policy_caching_optimized
  }

  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = local.lambda_origin_id
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS"]
    cached_methods           = ["GET", "HEAD"]
    compress                 = true
    cache_policy_id          = local.cloudfront_managed_cache_policy_caching_disabled
    origin_request_policy_id = local.cloudfront_managed_origin_request_all_viewer_except_host
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.site.certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }
}

# These are apex records inside the delegated subdomain hosted zone. For a zone
# named ct.example.com, they serve ct.example.com itself.
resource "aws_route53_record" "site_a" {
  name    = var.domain_name
  type    = "A"
  zone_id = aws_route53_zone.site.zone_id

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
  }
}

resource "aws_route53_record" "site_aaaa" {
  name    = var.domain_name
  type    = "AAAA"
  zone_id = aws_route53_zone.site.zone_id

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.site.domain_name
    zone_id                = aws_cloudfront_distribution.site.hosted_zone_id
  }
}

data "aws_iam_policy_document" "site_bucket" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.site_bucket.json
}

# This grants CloudFront, and only this distribution, permission to invoke the
# IAM-protected Lambda Function URL.
resource "aws_lambda_permission" "allow_cloudfront" {
  statement_id           = "AllowCloudFrontInvokeFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.api.function_name
  principal              = "cloudfront.amazonaws.com"
  source_account         = data.aws_caller_identity.current.account_id
  source_arn             = aws_cloudfront_distribution.site.arn
  function_url_auth_type = "AWS_IAM"
}

resource "aws_lambda_permission" "allow_cloudfront_invoke_function" {
  statement_id             = "AllowCloudFrontInvokeFunctionViaUrl"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.api.function_name
  principal                = "cloudfront.amazonaws.com"
  source_account           = data.aws_caller_identity.current.account_id
  source_arn               = aws_cloudfront_distribution.site.arn
  invoked_via_function_url = true
}

# Optional budget guardrail for unexpected edge or Lambda spend.
resource "aws_budgets_budget" "monthly" {
  count = var.budget_alert_email == "" ? 0 : 1

  name         = "${var.name_prefix}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "ACTUAL"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    notification_type          = "FORECASTED"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
