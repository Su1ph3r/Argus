# Nubicustos Test Fixtures

> **WARNING**: These configurations are **intentionally vulnerable** and should **NEVER** be deployed to any real environment. They exist solely for testing Nubicustos security scanning capabilities.

This directory contains intentionally vulnerable Infrastructure-as-Code (IaC) configurations for testing Nubicustos security scanners including:
- **Checkov** - Multi-framework IaC scanner
- **tfsec** - Terraform security scanner
- **Terrascan** - Policy-as-code engine
- **kube-bench** - CIS Kubernetes Benchmark
- **Kubescape** - NSA/MITRE ATT&CK frameworks
- **kube-linter** - Kubernetes best practices
- **Polaris** - Kubernetes configuration validation
- **Trivy** - Vulnerability scanner

## Directory Structure

```
test-fixtures/
├── terraform/
│   └── aws/
│       ├── providers.tf      # Hardcoded AWS credentials
│       ├── s3.tf             # Insecure S3 buckets
│       ├── ec2.tf            # Insecure EC2/Security Groups
│       ├── iam.tf            # Overly permissive IAM
│       ├── rds.tf            # Insecure RDS instances
│       ├── lambda.tf         # Insecure Lambda functions
│       ├── cloudtrail.tf     # Misconfigured CloudTrail
│       └── kms.tf            # Weak KMS configurations
├── kubernetes/
│   ├── privileged-pod.yaml       # Privileged containers
│   ├── insecure-deployment.yaml  # Multiple misconfigs
│   ├── insecure-service.yaml     # Exposed services
│   ├── insecure-rbac.yaml        # Overly permissive RBAC
│   ├── insecure-secrets.yaml     # Hardcoded secrets
│   ├── insecure-psp.yaml         # Permissive PSP
│   ├── insecure-networkpolicy.yaml # Open network policies
│   └── crypto-miner-simulation.yaml # Malicious workload patterns
└── helm/
    └── vulnerable-app/
        ├── Chart.yaml
        ├── values.yaml           # Hardcoded credentials
        └── templates/
            ├── _helpers.tpl
            ├── deployment.yaml
            ├── service.yaml
            ├── ingress.yaml
            └── secrets.yaml
```

## Vulnerability Coverage

### Terraform/AWS Vulnerabilities

| File | Vulnerability | Checkov ID | Description |
|------|--------------|------------|-------------|
| `providers.tf` | Hardcoded AWS credentials | CKV_AWS_41 | AWS access keys in provider config |
| `s3.tf` | Public S3 bucket | CKV_AWS_20 | S3 bucket with public-read-write ACL |
| `s3.tf` | No S3 encryption | CKV_AWS_19 | Missing server-side encryption |
| `s3.tf` | No S3 versioning | CKV_AWS_21 | Versioning not enabled |
| `s3.tf` | No S3 logging | CKV_AWS_18 | Access logging not enabled |
| `s3.tf` | Public bucket policy | CKV_AWS_70 | Policy allows Principal: "*" |
| `s3.tf` | No MFA delete | CKV_AWS_52 | MFA delete not enabled |
| `ec2.tf` | SSH open to world | CKV_AWS_24 | 0.0.0.0/0 to port 22 |
| `ec2.tf` | RDP open to world | CKV_AWS_25 | 0.0.0.0/0 to port 3389 |
| `ec2.tf` | IMDSv1 enabled | CKV_AWS_79 | http_tokens = optional |
| `ec2.tf` | Unencrypted EBS | CKV_AWS_3 | encrypted = false |
| `ec2.tf` | Public IP on EC2 | CKV_AWS_88 | associate_public_ip_address = true |
| `ec2.tf` | No detailed monitoring | CKV_AWS_135 | monitoring = false |
| `ec2.tf` | Hardcoded secrets in user_data | - | AWS keys and passwords in user_data |
| `iam.tf` | Admin policy (Action: *) | CKV_AWS_1 | Full administrative privileges |
| `iam.tf` | Wildcard principal | CKV_AWS_61 | AssumeRole allows Principal: "*" |
| `iam.tf` | Inline policies | CKV_AWS_40 | IAM user with inline policy |
| `iam.tf` | Dangerous IAM perms | - | iam:PassRole, lambda:CreateFunction, etc. |
| `rds.tf` | Publicly accessible | CKV_AWS_16 | publicly_accessible = true |
| `rds.tf` | Unencrypted storage | CKV_AWS_17 | storage_encrypted = false |
| `rds.tf` | No enhanced monitoring | CKV_AWS_118 | monitoring_interval = 0 |
| `rds.tf` | No deletion protection | CKV_AWS_133 | deletion_protection = false |
| `rds.tf` | No IAM auth | CKV_AWS_157 | iam_database_authentication_enabled = false |
| `rds.tf` | Hardcoded password | CKV_AWS_96 | Password in plain text |
| `lambda.tf` | No DLQ | CKV_AWS_116 | Missing dead_letter_config |
| `lambda.tf` | Not in VPC | CKV_AWS_117 | Missing vpc_config |
| `lambda.tf` | No X-Ray | CKV_AWS_50 | Missing tracing_config |
| `lambda.tf` | Secrets in env vars | CKV_AWS_173 | Credentials in environment |
| `lambda.tf` | Public invoke | CKV_AWS_62 | Principal: "*" can invoke |
| `lambda.tf` | Public URL | CKV_AWS_258 | authorization_type = "NONE" |
| `cloudtrail.tf` | No CMK encryption | CKV_AWS_35 | Missing kms_key_id |
| `cloudtrail.tf` | No log validation | CKV_AWS_36 | enable_log_file_validation = false |
| `cloudtrail.tf` | Not multi-region | CKV_AWS_78 | is_multi_region_trail = false |
| `cloudtrail.tf` | No CloudWatch | CKV_AWS_252 | Missing cloud_watch_logs_group_arn |
| `kms.tf` | No key rotation | CKV_AWS_33 | enable_key_rotation = false |
| `kms.tf` | Permissive policy | CKV_AWS_227 | Principal: "*" with kms:* |

### Kubernetes Vulnerabilities

| File | Vulnerability | Framework | Description |
|------|--------------|-----------|-------------|
| `privileged-pod.yaml` | Privileged container | CIS, NSA | privileged: true |
| `privileged-pod.yaml` | Root user | CIS, NSA | runAsUser: 0 |
| `privileged-pod.yaml` | Host namespaces | CIS, NSA | hostNetwork/hostPID/hostIPC: true |
| `privileged-pod.yaml` | Docker socket mount | CIS, NSA | /var/run/docker.sock mounted |
| `privileged-pod.yaml` | Host filesystem mount | CIS, NSA | / mounted to container |
| `privileged-pod.yaml` | ALL capabilities | CIS, NSA | capabilities.add: [ALL] |
| `privileged-pod.yaml` | Latest tag | Best Practice | image: nginx:latest |
| `insecure-deployment.yaml` | No resource limits | Best Practice | resources: {} |
| `insecure-deployment.yaml` | No security context | CIS, NSA | Missing securityContext |
| `insecure-deployment.yaml` | Hardcoded secrets | Best Practice | Credentials in env vars |
| `insecure-deployment.yaml` | Service account token | CIS | automountServiceAccountToken: true |
| `insecure-deployment.yaml` | No probes | Best Practice | Missing liveness/readiness |
| `insecure-service.yaml` | LoadBalancer exposed | Best Practice | type: LoadBalancer |
| `insecure-service.yaml` | No TLS | Best Practice | Ingress without TLS |
| `insecure-service.yaml` | Wildcard host | Best Practice | Ingress matches all hosts |
| `insecure-rbac.yaml` | Wildcard permissions | CIS, NSA | resources: ["*"], verbs: ["*"] |
| `insecure-rbac.yaml` | Cluster-admin binding | CIS, NSA | Default SA with cluster-admin |
| `insecure-rbac.yaml` | Secrets access | CIS | Role can read kube-system secrets |
| `insecure-rbac.yaml` | Pod exec | CIS | pods/exec permission |
| `insecure-rbac.yaml` | Impersonation | CIS | Can impersonate users |
| `insecure-secrets.yaml` | Base64 "encryption" | Best Practice | Secrets easily decoded |
| `insecure-secrets.yaml` | AWS creds in secrets | Best Practice | Should use IRSA |
| `insecure-secrets.yaml` | Sensitive ConfigMap | Best Practice | Passwords in ConfigMap |
| `insecure-psp.yaml` | Permissive PSP | CIS | All capabilities allowed |
| `insecure-psp.yaml` | Privileged namespace | PSS | pod-security: privileged |
| `insecure-networkpolicy.yaml` | Allow all ingress | CIS | Empty ingress: [{}] |
| `insecure-networkpolicy.yaml` | Allow all egress | CIS | Empty egress: [{}] |
| `insecure-networkpolicy.yaml` | No default deny | CIS | Missing default-deny policy |
| `crypto-miner-simulation.yaml` | Miner image | Falco | Known miner container |
| `crypto-miner-simulation.yaml` | High CPU requests | Behavioral | Typical mining pattern |
| `crypto-miner-simulation.yaml` | Suspicious commands | Falco | Mining pool connections |

### Helm Chart Vulnerabilities

| File | Vulnerability | Description |
|------|--------------|-------------|
| `values.yaml` | Hardcoded credentials | Database, AWS, API keys in values |
| `values.yaml` | Latest tag | image.tag: latest |
| `values.yaml` | No resource limits | resources: {} |
| `values.yaml` | Privileged context | Full privileged container |
| `values.yaml` | Host access | hostNetwork/PID/IPC enabled |
| `values.yaml` | No TLS | ingress.tls: [] |
| `values.yaml` | Host path mounts | Docker socket and root FS |
| `values.yaml` | No probes | Empty liveness/readiness |
| `templates/deployment.yaml` | Secrets in env | Credentials from values in env vars |
| `templates/secrets.yaml` | Plaintext secrets | Credentials in Secret manifest |

## Running Scans

### Checkov (Terraform)
```bash
checkov -d test-fixtures/terraform/aws/
```

### tfsec
```bash
tfsec test-fixtures/terraform/aws/
```

### Terrascan
```bash
terrascan scan -i terraform -d test-fixtures/terraform/aws/
```

### Checkov (Kubernetes)
```bash
checkov -d test-fixtures/kubernetes/
```

### Kubescape
```bash
kubescape scan test-fixtures/kubernetes/
```

### kube-linter
```bash
kube-linter lint test-fixtures/kubernetes/
```

### Polaris
```bash
polaris audit --audit-path test-fixtures/kubernetes/
```

### Checkov (Helm)
```bash
checkov -d test-fixtures/helm/vulnerable-app/
```

### Trivy (IaC)
```bash
trivy config test-fixtures/
```

## Expected Findings

When running scans against these fixtures, you should see:

- **Terraform**: 40+ findings across S3, EC2, IAM, RDS, Lambda, CloudTrail, KMS
- **Kubernetes**: 50+ findings for privileged containers, RBAC, secrets, network policies
- **Helm**: 20+ findings for hardcoded credentials, privileged settings, missing security

If any scanner returns 0 findings, the scanner configuration may need adjustment.

## Adding New Test Cases

When adding new vulnerable configurations:

1. Include inline comments documenting the vulnerability
2. Reference the relevant Checkov/CIS ID where applicable
3. Update this README with the new vulnerabilities
4. Verify scanners detect the new issues

## Disclaimer

These configurations represent common security misconfigurations found in real-world environments. They are provided for educational and testing purposes only. Never deploy these to production systems.
