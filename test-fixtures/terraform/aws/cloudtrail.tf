# Intentionally Vulnerable CloudTrail Configuration
# For testing Nubicustos IaC scanners

# VULN: CloudTrail without encryption or log validation
resource "aws_cloudtrail" "vulnerable_trail" {
  name           = "vulnerable-trail"
  s3_bucket_name = aws_s3_bucket.trail_bucket.id

  # CKV_AWS_35: CloudTrail is not encrypted with CMK
  # Missing: kms_key_id

  # CKV_AWS_36: CloudTrail log file validation is not enabled
  enable_log_file_validation = false

  # CKV_AWS_67: CloudTrail is not logging management events
  event_selector {
    read_write_type           = "WriteOnly"  # Should be "All"
    include_management_events = false
  }

  # CKV_AWS_78: CloudTrail is not multi-region
  is_multi_region_trail = false

  # CKV_AWS_252: CloudTrail is not integrated with CloudWatch Logs
  # Missing: cloud_watch_logs_group_arn

  tags = {
    Name = "Vulnerable Trail"
  }
}

# VULN: Trail bucket without proper security
resource "aws_s3_bucket" "trail_bucket" {
  bucket = "cloudtrail-logs-vulnerable"
  # Missing: encryption, versioning, logging, access logging
}

# VULN: Trail bucket policy allows public access
resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.trail_bucket.arn}/*"
      }
    ]
  })
}
