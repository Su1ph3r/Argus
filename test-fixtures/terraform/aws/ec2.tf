# Intentionally Vulnerable EC2 Configuration
# For testing Nubicustos IaC scanners

# VULN: Security group allows all inbound traffic
resource "aws_security_group" "allow_all" {
  name        = "allow_all_traffic"
  description = "Intentionally insecure - allows all traffic"
  vpc_id      = "vpc-12345678"

  # CKV_AWS_24: Security group allows ingress from 0.0.0.0/0 to port 22
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  # CKV_AWS_25: Security group allows ingress from 0.0.0.0/0 to port 3389
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP from anywhere"
  }

  # VULN: All ports open
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All TCP ports open"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULN: EC2 instance with IMDSv1, no encryption, public IP
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # CKV_AWS_79: IMDSv2 is not required
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # Should be "required" for IMDSv2
  }

  # CKV_AWS_8: EBS volume not encrypted
  root_block_device {
    volume_size = 20
    encrypted   = false
  }

  # CKV_AWS_88: EC2 instance has public IP
  associate_public_ip_address = true

  # CKV_AWS_135: EC2 instance does not have detailed monitoring enabled
  monitoring = false

  vpc_security_group_ids = [aws_security_group.allow_all.id]

  # VULN: User data with hardcoded credentials
  user_data = <<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    export DB_PASSWORD="SuperSecretPassword123!"
  EOF

  tags = {
    Name = "Vulnerable Instance"
  }
}

# VULN: EBS volume without encryption
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # CKV_AWS_3: EBS volume not encrypted

  tags = {
    Name = "Unencrypted Volume"
  }
}

# VULN: Launch template without encryption
resource "aws_launch_template" "vulnerable" {
  name = "vulnerable-template"

  # Missing: metadata_options with http_tokens = "required"
  # Missing: encrypted block device mappings

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      encrypted   = false
    }
  }
}
