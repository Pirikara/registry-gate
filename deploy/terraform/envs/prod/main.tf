terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "registory-gate-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "ap-northeast-1"
    encrypt        = true
    dynamodb_table = "registory-gate-tfstate-lock"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "registory-gate"
      Environment = "prod"
      ManagedBy   = "terraform"
    }
  }
}

# ------------------------------------------------------------------ #
# VPC (simple: 2 AZ, public + private + data subnets)
# ------------------------------------------------------------------ #
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "registory-gate-${var.env}"
  cidr = var.vpc_cidr

  azs              = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnets   = var.public_subnets
  private_subnets  = var.private_subnets
  database_subnets = var.database_subnets

  enable_nat_gateway   = true
  single_nat_gateway   = false  # one NAT per AZ for HA
  enable_dns_hostnames = true
  enable_dns_support   = true

  create_database_subnet_group = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ------------------------------------------------------------------ #
# ECR
# ------------------------------------------------------------------ #
module "ecr" {
  source = "../../modules/ecr"

  images = ["proxy", "admin"]
  prefix = "registory-gate"
}

# ------------------------------------------------------------------ #
# ALB
# ------------------------------------------------------------------ #
module "alb" {
  source = "../../modules/alb"

  name            = "registory-gate-${var.env}"
  vpc_id          = module.vpc.vpc_id
  public_subnets  = module.vpc.public_subnets
  certificate_arn = var.acm_certificate_arn
  waf_arn         = module.waf.arn
}

# ------------------------------------------------------------------ #
# WAF (attach to ALB)
# ------------------------------------------------------------------ #
resource "aws_wafv2_web_acl" "this" {
  name  = "registory-gate-${var.env}"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ratelimit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-managed-common"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awscommon"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "registory-gate-waf"
    sampled_requests_enabled   = true
  }
}

module "waf" {
  source = "../../modules/alb"  # placeholder; real projects use a dedicated WAF module
  count  = 0                    # WAF is created inline above
  name   = ""
  vpc_id = ""
  public_subnets  = []
  certificate_arn = ""
  waf_arn         = ""
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = module.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# ------------------------------------------------------------------ #
# Aurora PostgreSQL Serverless v2
# ------------------------------------------------------------------ #
module "rds" {
  source = "../../modules/rds"

  name             = "registory-gate-${var.env}"
  vpc_id           = module.vpc.vpc_id
  subnet_group     = module.vpc.database_subnet_group_name
  allowed_sg_ids   = [module.ecs.security_group_id]
  db_name          = "registory_gate"
  master_username  = "rg_admin"
  master_password  = var.db_master_password  # injected via Secrets Manager in prod
  min_acu          = 0.5
  max_acu          = 8
}

# ------------------------------------------------------------------ #
# ElastiCache Redis (cluster mode)
# ------------------------------------------------------------------ #
module "redis" {
  source = "../../modules/redis"

  name           = "registory-gate-${var.env}"
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.private_subnets
  allowed_sg_ids = [module.ecs.security_group_id]
  node_type      = "cache.t4g.small"
  num_nodes      = 2
}

# ------------------------------------------------------------------ #
# ECS Fargate cluster + services
# ------------------------------------------------------------------ #
module "ecs" {
  source = "../../modules/ecs"

  cluster_name    = "registory-gate-${var.env}"
  vpc_id          = module.vpc.vpc_id
  private_subnets = module.vpc.private_subnets

  proxy_image = "${module.ecr.repo_urls["proxy"]}:latest"
  admin_image = "${module.ecr.repo_urls["admin"]}:latest"

  proxy_target_group_arn = module.alb.proxy_target_group_arn
  admin_target_group_arn = module.alb.admin_target_group_arn

  database_url = module.rds.connection_string_ssm_arn
  redis_addr   = module.redis.primary_endpoint

  log_group = aws_cloudwatch_log_group.ecs.name
}

# ------------------------------------------------------------------ #
# CloudWatch Log Group
# ------------------------------------------------------------------ #
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/registory-gate/${var.env}"
  retention_in_days = 90
}

# ------------------------------------------------------------------ #
# Route 53
# ------------------------------------------------------------------ #
data "aws_route53_zone" "this" {
  name = var.hosted_zone_name
}

resource "aws_route53_record" "npm" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "npm.${var.hosted_zone_name}"
  type    = "A"
  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "pypi" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "pypi.${var.hosted_zone_name}"
  type    = "A"
  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "admin" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "admin.${var.hosted_zone_name}"
  type    = "A"
  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = true
  }
}
