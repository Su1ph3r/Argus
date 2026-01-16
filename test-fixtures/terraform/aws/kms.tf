# Intentionally Vulnerable KMS Configuration
# For testing Nubicustos IaC scanners

# VULN: KMS key with overly permissive policy
resource "aws_kms_key" "vulnerable_key" {
  description             = "Vulnerable KMS key for testing"
  deletion_window_in_days = 7

  # CKV_AWS_33: KMS key rotation is not enabled
  enable_key_rotation = false

  # CKV_AWS_227: KMS key has overly permissive policy
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # Allows any AWS principal
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "Vulnerable Key"
  }
}

# VULN: KMS key without proper grants management
resource "aws_kms_grant" "overly_permissive" {
  name              = "overly-permissive-grant"
  key_id            = aws_kms_key.vulnerable_key.key_id
  grantee_principal = "arn:aws:iam::111122223333:root"

  operations = [
    "Encrypt",
    "Decrypt",
    "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext",
    "ReEncryptFrom",
    "ReEncryptTo",
    "CreateGrant",
    "DescribeKey"
  ]

  # Grants can be used to delegate permissions
}
