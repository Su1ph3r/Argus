# Terraform Provider Configuration
# For testing Nubicustos IaC scanners

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  # VULN: Hardcoded credentials (for testing scanner detection)
  # CKV_AWS_41: Hardcoded AWS access key
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

  default_tags {
    tags = {
      Environment = "test"
      Project     = "nubicustos-testing"
    }
  }
}
