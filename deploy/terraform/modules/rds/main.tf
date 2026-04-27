variable "name"            { type = string }
variable "vpc_id"          { type = string }
variable "subnet_group"    { type = string }
variable "allowed_sg_ids"  { type = list(string) }
variable "db_name"         { type = string }
variable "master_username" { type = string }
variable "master_password" { type = string; sensitive = true }
variable "min_acu"         { type = number; default = 0.5 }
variable "max_acu"         { type = number; default = 8 }

resource "aws_security_group" "rds" {
  name        = "${var.name}-rds"
  description = "Aurora PostgreSQL access"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_sg_ids
  }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier      = var.name
  engine                  = "aurora-postgresql"
  engine_mode             = "provisioned"
  engine_version          = "16.1"
  database_name           = var.db_name
  master_username         = var.master_username
  master_password         = var.master_password
  db_subnet_group_name    = var.subnet_group
  vpc_security_group_ids  = [aws_security_group.rds.id]

  serverlessv2_scaling_configuration {
    min_capacity = var.min_acu
    max_capacity = var.max_acu
  }

  backup_retention_period   = 7
  preferred_backup_window   = "03:00-04:00"
  deletion_protection       = true
  storage_encrypted         = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"
}

resource "aws_rds_cluster_instance" "writer" {
  identifier         = "${var.name}-writer"
  cluster_identifier = aws_rds_cluster.this.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.this.engine
  engine_version     = aws_rds_cluster.this.engine_version
}

resource "aws_rds_cluster_instance" "reader" {
  identifier         = "${var.name}-reader"
  cluster_identifier = aws_rds_cluster.this.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.this.engine
  engine_version     = aws_rds_cluster.this.engine_version
}

# Store connection string in SSM Parameter Store (not Secrets Manager) for simplicity.
# Production should use Secrets Manager with rotation.
resource "aws_ssm_parameter" "db_url" {
  name  = "/${var.name}/DATABASE_URL"
  type  = "SecureString"
  value = "postgres://${var.master_username}:${var.master_password}@${aws_rds_cluster.this.endpoint}:5432/${var.db_name}?sslmode=require"
}

output "endpoint"                { value = aws_rds_cluster.this.endpoint }
output "reader_endpoint"         { value = aws_rds_cluster.this.reader_endpoint }
output "connection_string_ssm_arn" { value = aws_ssm_parameter.db_url.arn }
