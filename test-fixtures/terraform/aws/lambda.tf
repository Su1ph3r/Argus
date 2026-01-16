# Intentionally Vulnerable Lambda Configuration
# For testing Nubicustos IaC scanners

# VULN: Lambda function with overly permissive role
resource "aws_lambda_function" "vulnerable_function" {
  filename      = "lambda.zip"
  function_name = "vulnerable-function"
  role          = aws_iam_role.lambda_admin.arn
  handler       = "index.handler"
  runtime       = "python3.8"  # CKV_AWS_173: Outdated runtime

  # CKV_AWS_116: Lambda function not configured with DLQ
  # Missing: dead_letter_config

  # CKV_AWS_117: Lambda function not in VPC
  # Missing: vpc_config

  # CKV_AWS_50: X-Ray tracing not enabled
  # Missing: tracing_config

  # CKV_AWS_173: Lambda environment variables not encrypted with CMK
  environment {
    variables = {
      DB_PASSWORD    = "SuperSecretPassword123!"
      API_KEY        = "sk-1234567890abcdef"
      AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    }
  }

  # CKV_AWS_115: Lambda function not configured with function-level concurrent execution limit
  reserved_concurrent_executions = -1

  timeout     = 300
  memory_size = 128

  tags = {
    Name = "Vulnerable Lambda"
  }
}

# VULN: Lambda role with admin privileges
resource "aws_iam_role" "lambda_admin" {
  name = "lambda-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# VULN: Full admin policy attached to Lambda
resource "aws_iam_role_policy" "lambda_admin_policy" {
  name = "lambda-admin-policy"
  role = aws_iam_role.lambda_admin.id

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

# VULN: Lambda permission allows any AWS account to invoke
resource "aws_lambda_permission" "allow_all" {
  statement_id  = "AllowExecutionFromAnyAccount"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.vulnerable_function.function_name
  principal     = "*"  # CKV_AWS_62: Lambda function can be invoked by anyone
}

# VULN: Lambda with publicly accessible URL
resource "aws_lambda_function_url" "public_url" {
  function_name      = aws_lambda_function.vulnerable_function.function_name
  authorization_type = "NONE"  # CKV_AWS_258: Lambda URL allows unauthenticated access
}
