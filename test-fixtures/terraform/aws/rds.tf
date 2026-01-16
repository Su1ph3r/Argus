# Intentionally Vulnerable RDS Configuration
# For testing Nubicustos IaC scanners

# VULN: RDS instance with multiple security issues
resource "aws_db_instance" "vulnerable_db" {
  identifier        = "vulnerable-database"
  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "mydb"
  username = "admin"
  password = "Password123!"  # CKV_AWS_96: Hardcoded password

  # CKV_AWS_16: RDS instance is publicly accessible
  publicly_accessible = true

  # CKV_AWS_17: RDS instance storage is not encrypted
  storage_encrypted = false

  # CKV_AWS_118: RDS instance does not have enhanced monitoring
  monitoring_interval = 0

  # CKV_AWS_133: RDS instance does not have deletion protection
  deletion_protection = false

  # CKV_AWS_157: RDS instance does not have IAM authentication
  iam_database_authentication_enabled = false

  # CKV_AWS_226: RDS instance does not have auto minor version upgrade
  auto_minor_version_upgrade = false

  # CKV_AWS_161: RDS instance does not have multi-az enabled
  multi_az = false

  # Missing: backup_retention_period
  backup_retention_period = 0

  # CKV_AWS_129: RDS instance does not have copy tags to snapshot
  copy_tags_to_snapshot = false

  skip_final_snapshot = true

  tags = {
    Name = "Vulnerable Database"
  }
}

# VULN: DB security group allows all access
resource "aws_db_security_group" "default" {
  name = "vulnerable-db-sg"

  ingress {
    cidr = "0.0.0.0/0"  # CKV_AWS_23: DB security group allows 0.0.0.0/0
  }
}

# VULN: RDS cluster without encryption
resource "aws_rds_cluster" "vulnerable_cluster" {
  cluster_identifier = "vulnerable-aurora-cluster"
  engine             = "aurora-mysql"
  engine_version     = "5.7.mysql_aurora.2.10.2"

  database_name   = "mydb"
  master_username = "admin"
  master_password = "VeryWeakPassword1"

  # Missing encryption
  storage_encrypted = false

  # No backup retention
  backup_retention_period = 0

  # Missing deletion protection
  deletion_protection = false

  skip_final_snapshot = true
}

# VULN: DB subnet group with public subnets
resource "aws_db_subnet_group" "public" {
  name       = "public-db-subnet-group"
  subnet_ids = ["subnet-public-1", "subnet-public-2"]

  tags = {
    Name = "Public DB Subnet Group"
  }
}
