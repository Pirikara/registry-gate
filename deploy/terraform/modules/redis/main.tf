variable "name"           { type = string }
variable "vpc_id"         { type = string }
variable "subnet_ids"     { type = list(string) }
variable "allowed_sg_ids" { type = list(string) }
variable "node_type"      { type = string; default = "cache.t4g.small" }
variable "num_nodes"      { type = number; default = 2 }

resource "aws_security_group" "redis" {
  name        = "${var.name}-redis"
  description = "ElastiCache Redis"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = var.allowed_sg_ids
  }
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-redis"
  subnet_ids = var.subnet_ids
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = var.name
  description          = "Registry Gate metadata cache"
  node_type            = var.node_type
  num_cache_clusters   = var.num_nodes
  automatic_failover_enabled = var.num_nodes > 1

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  engine_version             = "7.1"

  apply_immediately = false
}

output "primary_endpoint" {
  value = aws_elasticache_replication_group.this.primary_endpoint_address
}
