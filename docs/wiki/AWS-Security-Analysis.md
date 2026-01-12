# AWS Security Analysis

Nubicustos provides deep AWS security analysis beyond standard compliance scanning, including IMDS checks, Lambda analysis, privilege escalation discovery, and more.

## Overview

AWS-specific security features include:

| Feature | Description | Tools |
|---------|-------------|-------|
| IMDS Checks | EC2 metadata service vulnerabilities | Custom analysis |
| Lambda Analysis | Serverless security assessment | Custom analysis |
| Privilege Escalation | IAM lateral movement paths | Custom analysis |
| Public Exposures | Attack surface monitoring | CloudFox, Custom |
| Exposed Credentials | Credential leak detection | Custom analysis |
| Assumed Roles | Cross-account role analysis | Custom analysis |
| CloudFox | Attack surface enumeration | CloudFox |
| Enumerate IAM | Permission mapping | enumerate-iam |
| Pacu | Exploitation testing | Pacu |

## IMDS Checks

### What is IMDS?

The Instance Metadata Service (IMDS) provides EC2 instances with access to instance metadata, including IAM role credentials. IMDSv1 is vulnerable to SSRF attacks.

### Vulnerabilities Detected

| Check | Risk | Description |
|-------|------|-------------|
| IMDSv1 Enabled | High | Instance allows unauthenticated metadata requests |
| Hop Limit | Medium | Token hop limit allows container credential theft |
| Instance Profile | Context | Overprivileged instance role |

### API Endpoint

```bash
curl http://localhost:8000/api/imds-checks
```

Response:
```json
{
  "instances": [
    {
      "instance_id": "i-1234567890abcdef0",
      "imds_version": "v1",
      "hop_limit": 1,
      "role_arn": "arn:aws:iam::123456789012:role/WebServer",
      "risk_level": "high",
      "remediation": "aws ec2 modify-instance-metadata-options..."
    }
  ]
}
```

### Remediation

Enforce IMDSv2:
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

## Lambda Analysis

### Security Checks

| Check | Risk | Description |
|-------|------|-------------|
| Overprivileged Role | High | Role has unnecessary permissions |
| Environment Secrets | High | Sensitive data in env vars |
| VPC Configuration | Medium | Function not in VPC |
| Outdated Runtime | Medium | Using deprecated runtime |
| Public Function URL | High | Function accessible without auth |

### API Endpoint

```bash
curl http://localhost:8000/api/lambda-analysis
```

Response:
```json
{
  "functions": [
    {
      "function_name": "api-handler",
      "role_arn": "arn:aws:iam::123456789012:role/LambdaRole",
      "runtime": "python3.9",
      "vpc_id": null,
      "issues": [
        {
          "type": "environment_secrets",
          "severity": "high",
          "detail": "DATABASE_PASSWORD found in environment"
        }
      ]
    }
  ]
}
```

## Privilege Escalation Paths

### Detection Methods

The analyzer identifies IAM privilege escalation through:

1. **Policy Analysis** - Scanning for dangerous permissions
2. **Role Chaining** - Following role assumption paths
3. **Service Exploitation** - Identifying abusable services

### Dangerous Permissions

| Permission | Risk | Escalation Method |
|------------|------|-------------------|
| `iam:CreateAccessKey` | Critical | Create keys for any user |
| `iam:CreateLoginProfile` | Critical | Create console access |
| `iam:AttachUserPolicy` | Critical | Attach admin policy |
| `iam:PassRole` + `lambda:CreateFunction` | High | Pass admin role to Lambda |
| `sts:AssumeRole` on admin roles | High | Assume privileged role |
| `ec2:RunInstances` + `iam:PassRole` | High | Launch EC2 with admin role |

### API Endpoint

```bash
curl http://localhost:8000/api/privesc-paths
```

Response:
```json
{
  "paths": [
    {
      "principal": "arn:aws:iam::123456789012:user/developer",
      "target": "arn:aws:iam::123456789012:role/AdminRole",
      "method": "iam:CreateAccessKey",
      "steps": [
        "User can create access keys for any IAM user",
        "Create keys for user with admin policy attached",
        "Use new credentials for admin access"
      ],
      "risk_score": 95
    }
  ]
}
```

## Public Exposures

### Resources Monitored

| Resource | Exposure Type | Risk |
|----------|--------------|------|
| S3 Buckets | Public ACL/Policy | High |
| EC2 Instances | Public IP + Open Ports | High |
| Security Groups | 0.0.0.0/0 Ingress | Medium |
| RDS Instances | Publicly Accessible | High |
| ELB/ALB | Internet-Facing | Context |
| Lambda URLs | Public Endpoint | High |

### API Endpoint

```bash
curl http://localhost:8000/api/public-exposures
```

Response:
```json
{
  "exposures": [
    {
      "resource_type": "s3_bucket",
      "resource_id": "arn:aws:s3:::company-data",
      "exposure_type": "public_acl",
      "severity": "critical",
      "detail": "Bucket has public-read ACL"
    }
  ]
}
```

## Exposed Credentials

### Detection Sources

Credentials are detected from:
- S3 bucket contents
- Lambda environment variables
- EC2 user data
- CloudFormation outputs
- SSM parameters

### Credential Types

| Type | Risk | Description |
|------|------|-------------|
| AWS Access Keys | Critical | IAM user credentials |
| Database Passwords | High | RDS/Aurora credentials |
| API Keys | High | Third-party service keys |
| Private Keys | Critical | SSH/TLS private keys |
| Secrets | Variable | Application secrets |

### API Endpoint

```bash
curl http://localhost:8000/api/exposed-credentials
```

## Assumed Roles

### Analysis Scope

- Trust policy analysis
- External account access
- Service-linked roles
- Cross-account patterns
- Federation configuration

### Risk Factors

| Factor | Risk | Description |
|--------|------|-------------|
| External Account Trust | High | Unknown accounts can assume role |
| Wildcard Principal | Critical | Any entity can assume role |
| Missing External ID | Medium | No additional verification |
| Overprivileged Role | Context | Role has excessive permissions |

### API Endpoint

```bash
curl http://localhost:8000/api/assumed-roles
```

## CloudFox Integration

CloudFox provides attack surface enumeration:

### Modules
- **credentials** - Find exposed credentials
- **endpoints** - Discover service endpoints
- **filesystems** - Analyze EFS/FSx
- **permissions** - Map IAM permissions
- **resource-trusts** - Find trust relationships

### Running CloudFox

Via API:
```bash
curl -X POST http://localhost:8000/api/cloudfox/run \
  -H "Content-Type: application/json" \
  -d '{"modules": ["permissions", "endpoints"]}'
```

### API Endpoint

```bash
curl http://localhost:8000/api/cloudfox
```

## Enumerate-IAM

Maps effective IAM permissions for all principals:

### Capabilities
- User permission enumeration
- Role permission enumeration
- Policy effectiveness analysis
- Service control policy impact
- Permission boundary analysis

### API Endpoint

```bash
curl http://localhost:8000/api/enumerate-iam
```

Response:
```json
{
  "principals": [
    {
      "arn": "arn:aws:iam::123456789012:user/developer",
      "type": "user",
      "effective_permissions": [
        "s3:GetObject",
        "s3:PutObject",
        "ec2:Describe*"
      ],
      "attached_policies": [
        "arn:aws:iam::123456789012:policy/DeveloperPolicy"
      ]
    }
  ]
}
```

## Pacu Integration

Pacu is an AWS exploitation framework for authorized testing.

### Available Modules

| Category | Modules |
|----------|---------|
| Enumeration | `iam__enum_users`, `ec2__enum` |
| Privilege Escalation | `iam__privesc_scan` |
| Persistence | `iam__backdoor_users_keys` |
| Credential Access | `sts__assume_role` |

### Running Pacu

Via API:
```bash
curl -X POST http://localhost:8000/api/pacu/run \
  -H "Content-Type: application/json" \
  -d '{"module": "iam__privesc_scan"}'
```

### API Endpoint

```bash
curl http://localhost:8000/api/pacu
```

## Web Frontend Views

Access these features in the web frontend:

| Path | Feature |
|------|---------|
| `/imds-checks` | IMDS vulnerability list |
| `/lambda-analysis` | Lambda security issues |
| `/privesc-paths` | Privilege escalation paths |
| `/public-exposures` | Attack surface |
| `/exposed-credentials` | Credential leaks |
| `/assumed-roles` | Role assumption analysis |
| `/cloudfox` | CloudFox results |
| `/enumerate-iam` | IAM permissions |
| `/pacu` | Pacu findings |

## Best Practices

### Prioritization
1. Critical exposed credentials - Rotate immediately
2. Public S3 buckets with sensitive data
3. IMDSv1 on instances with privileged roles
4. Privilege escalation paths to admin
5. Lambda functions with secrets in env vars

### Continuous Monitoring
- Schedule regular scans
- Alert on new public exposures
- Monitor role assumption patterns
- Track privilege escalation paths

---

*See also: [[Attack Path Analysis|Attack-Path-Analysis]], [[Security Tools Reference|Security-Tools-Reference]]*
