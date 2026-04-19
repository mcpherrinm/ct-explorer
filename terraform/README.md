# Terraform Deployment

This scaffold deploys the infrastructure for a fresh AWS account:

- private S3 bucket for static site files
- public Route53 hosted zone for the app subdomain
- ACM certificate for the CloudFront domain
- Lambda Function URL for `/api/analyze`
- CloudFront in front of both origins
- CloudFront Origin Access Control for S3 and Lambda
- Route53 validation and CloudFront alias records
- AWS WAF rate limiting for the CloudFront distribution
- Lambda reserved concurrency to cap backend spend
- optional AWS Budget alerts

The regional resources default to `us-west-2`. CloudFront is global. AWS WAF web ACLs for CloudFront distributions and CloudFront ACM certificates are managed through `us-east-1`, so those resources set `region = "us-east-1"` inline.

The S3 bucket name and domain name are Terraform variables. In CI, set them with `TF_VAR_site_bucket_name` and `TF_VAR_domain_name`. The domain should be the delegated app subdomain, such as `ct.jordan-wright.com`.

The Lambda is not attached to a VPC. That is intentional: Lambda functions outside a VPC have outbound internet access by default, and this app needs to connect to public HTTPS hosts and CT logs. Avoiding a VPC also avoids NAT gateway cost.

The Lambda execution role is intentionally unprivileged. It has only the Lambda trust policy and no attached AWS API permissions. CloudFront invokes the Function URL through a resource-based Lambda permission, not through the function's execution role.

## Package the Lambda

From the repository root:

```sh
mkdir -p dist
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/bootstrap ./cmd/lambda
(cd dist && zip -q bootstrap.zip bootstrap)
```

## Deploy

```sh
cd terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

Terraform does not upload files from `web/` into S3. Keep infrastructure and site artifact deployment separate:

```sh
aws s3 sync web/ "s3://$(terraform output -raw site_bucket_name)/" --delete
aws cloudfront create-invalidation \
  --distribution-id "$(terraform output -raw cloudfront_distribution_id)" \
  --paths "/*"
```

For a custom domain, set:

```hcl
domain_name = "ct.example.com"
```

This stack creates a public Route53 hosted zone for that exact subdomain. If the parent domain is hosted somewhere else, such as Cloudflare, delegate the subdomain there by creating an `NS` record:

```text
Name: ct
Type: NS
Value: the four servers from terraform output route53_name_servers
```

For a first deploy, run enough Terraform to create the hosted zone, add the `NS` delegation in the parent DNS provider, wait for it to resolve, then run the full apply. ACM certificate validation depends on the delegation being visible publicly.

Set `budget_alert_email` in `terraform.tfvars` to create a monthly budget. Leave it empty to skip budgets.

## CloudFront Flat-Rate Plan

The deployable AWS resources are managed here, but the CloudFront flat-rate pricing plan attachment is currently left as a manual step. After `terraform apply`, use the `cloudfront_distribution_id` output to attach the distribution to the desired CloudFront pricing plan in AWS.

Use the Free plan first if it is available in the account. It is a good fit for this project because it includes WAF/rate limiting and avoids overage-style CloudFront/WAF billing. Keep the Lambda reserved concurrency cap even with the flat plan, because requests that pass WAF can still reach Lambda.

## Suggested Defaults

```hcl
lambda_reserved_concurrency  = 10
lambda_timeout_seconds       = 10
lambda_memory_mb             = 256
edge_rate_limit_per_5_minutes = 1000
monthly_budget_usd           = "10"
```

Reserved concurrency caps concurrent Lambda executions. It does not keep warm instances running and does not cost money by itself.
