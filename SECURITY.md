# Security Policy

## Reporting

Please report security issues privately through GitHub Security Advisories for
this repository.

Good reports include:

- the affected endpoint, deployment path, or Terraform resource
- steps to reproduce
- expected and actual behavior
- impact, especially for SSRF, request amplification, or infrastructure cost
  risks

Please do not open public issues for suspected vulnerabilities until there is a
fix or mitigation available.

## Scope

The main security-sensitive area is the `/api/analyze` endpoint, because it
connects to user-supplied HTTPS hosts and CT logs. Reports about SSRF bypasses,
unsafe address handling, response disclosure, rate-limit bypasses, or deployment
configuration that can create unexpected public access are in scope.

This project is an educational tool and does not provide a security boundary for
certificate validation decisions.
