variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "env" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnets" {
  type    = list(string)
  default = ["10.0.0.0/24", "10.0.1.0/24"]
}

variable "private_subnets" {
  type    = list(string)
  default = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "database_subnets" {
  type    = list(string)
  default = ["10.0.20.0/24", "10.0.21.0/24"]
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the ALB (wildcard cert for *.example.com)"
  type        = string
}

variable "hosted_zone_name" {
  description = "Route 53 hosted zone name, e.g. registory-gate.example.com"
  type        = string
}

variable "db_master_password" {
  description = "Aurora master password — pass via TF_VAR_db_master_password or Secrets Manager"
  type        = string
  sensitive   = true
}

