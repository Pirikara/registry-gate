variable "name"            { type = string }
variable "vpc_id"          { type = string }
variable "public_subnets"  { type = list(string) }
variable "certificate_arn" { type = string }
variable "waf_arn"         { type = string; default = "" }

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "ALB inbound HTTPS"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  name               = var.name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnets

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.access_logs.bucket
    enabled = true
  }
}

resource "aws_s3_bucket" "access_logs" {
  bucket        = "${var.name}-alb-logs"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_lb_target_group" "proxy" {
  name        = "${var.name}-proxy"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
  }
}

resource "aws_lb_target_group" "admin" {
  name        = "${var.name}-admin"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path     = "/health"
    interval = 30
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

resource "aws_lb_listener_rule" "admin" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.admin.arn
  }

  condition {
    host_header {
      values = ["admin.*"]
    }
  }
}

output "arn"                    { value = aws_lb.this.arn }
output "dns_name"               { value = aws_lb.this.dns_name }
output "zone_id"                { value = aws_lb.this.zone_id }
output "proxy_target_group_arn" { value = aws_lb_target_group.proxy.arn }
output "admin_target_group_arn" { value = aws_lb_target_group.admin.arn }
output "security_group_id"      { value = aws_security_group.alb.id }
