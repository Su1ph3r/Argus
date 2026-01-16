# Intentionally Vulnerable IAM Configuration
# For testing Nubicustos IaC scanners

# VULN: IAM user with inline policy (should use managed policies)
resource "aws_iam_user" "admin_user" {
  name = "super-admin-user"
  # CKV_AWS_40: IAM user should not have inline policies
}

# VULN: Overly permissive admin policy
resource "aws_iam_user_policy" "admin_policy" {
  name = "admin-policy"
  user = aws_iam_user.admin_user.name

  # CKV_AWS_1: IAM policy allows full administrative privileges
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# VULN: IAM role with wildcard principal
resource "aws_iam_role" "overly_permissive" {
  name = "overly-permissive-role"

  # CKV_AWS_61: IAM role allows assume from any AWS account
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# VULN: Policy with dangerous permissions
resource "aws_iam_policy" "dangerous_policy" {
  name        = "dangerous-policy"
  description = "Intentionally dangerous policy for testing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DangerousS3Access"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid      = "DangerousIAMAccess"
        Effect   = "Allow"
        Action   = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:AttachUserPolicy",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
          "iam:PassRole"
        ]
        Resource = "*"
      },
      {
        Sid      = "DangerousLambdaAccess"
        Effect   = "Allow"
        Action   = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "lambda:UpdateFunctionCode"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULN: Access key for user (should use roles)
resource "aws_iam_access_key" "user_key" {
  user = aws_iam_user.admin_user.name
  # CKV_AWS_273: IAM access key is active
}

# VULN: Group with admin access
resource "aws_iam_group" "admins" {
  name = "admin-group"
}

resource "aws_iam_group_policy" "admin_group_policy" {
  name  = "admin-group-policy"
  group = aws_iam_group.admins.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
