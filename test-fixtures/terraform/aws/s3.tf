# Intentionally Vulnerable S3 Configuration
# For testing Nubicustos IaC scanners (Checkov, tfsec, Terrascan)

# VULN: Public bucket with no encryption, versioning, or logging
resource "aws_s3_bucket" "public_bucket" {
  bucket = "totally-public-bucket-12345"
  acl    = "public-read-write"  # CKV_AWS_20: S3 bucket has public ACL

  tags = {
    Name        = "Public Bucket"
    Environment = "test"
  }
}

# VULN: No server-side encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "unencrypted-data-bucket"
  # Missing: server_side_encryption_configuration - CKV_AWS_19
  # Missing: versioning - CKV_AWS_21
  # Missing: logging - CKV_AWS_18
}

# VULN: Bucket policy allows public access
resource "aws_s3_bucket_policy" "allow_public" {
  bucket = aws_s3_bucket.public_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # CKV_AWS_70: S3 bucket policy allows public access
        Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource  = ["${aws_s3_bucket.public_bucket.arn}/*"]
      }
    ]
  })
}

# VULN: No MFA delete, no lifecycle rules
resource "aws_s3_bucket" "sensitive_data" {
  bucket = "sensitive-customer-data"

  versioning {
    enabled    = true
    mfa_delete = false  # CKV_AWS_52: S3 bucket MFA delete is not enabled
  }
  # Missing: lifecycle_rule
  # Missing: replication_configuration
}
