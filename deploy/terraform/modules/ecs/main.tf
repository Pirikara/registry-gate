variable "cluster_name"    { type = string }
variable "vpc_id"          { type = string }
variable "private_subnets" { type = list(string) }

variable "proxy_image" { type = string }
variable "admin_image" { type = string }

variable "proxy_target_group_arn" { type = string }
variable "admin_target_group_arn" { type = string }

variable "database_url" { type = string }
variable "redis_addr"   { type = string }
variable "log_group"    { type = string }

# ------------------------------------------------------------------ #
# Cluster
# ------------------------------------------------------------------ #
resource "aws_ecs_cluster" "this" {
  name = var.cluster_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ------------------------------------------------------------------ #
# IAM: Task Execution Role
# ------------------------------------------------------------------ #
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "exec" {
  name               = "${var.cluster_name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "exec_basic" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow reading SSM parameters (DATABASE_URL stored as SecureString)
resource "aws_iam_role_policy" "exec_ssm" {
  name = "ssm-read"
  role = aws_iam_role.exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameters", "kms:Decrypt"]
      Resource = ["*"]
    }]
  })
}

# ------------------------------------------------------------------ #
# Security Group (ECS tasks)
# ------------------------------------------------------------------ #
resource "aws_security_group" "ecs" {
  name        = "${var.cluster_name}-ecs"
  description = "ECS Fargate tasks"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------------ #
# Proxy Service
# ------------------------------------------------------------------ #
resource "aws_ecs_task_definition" "proxy" {
  family                   = "${var.cluster_name}-proxy"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.exec.arn

  container_definitions = jsonencode([{
    name      = "proxy"
    image     = var.proxy_image
    essential = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]

    environment = [
      { name = "PORT",            value = "8080" },
      { name = "REDIS_ADDR",      value = var.redis_addr },
      { name = "MIGRATIONS_PATH", value = "/app/migrations" },
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = var.database_url },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_group
        awslogs-region        = "ap-northeast-1"
        awslogs-stream-prefix = "proxy"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_ecs_service" "proxy" {
  name            = "${var.cluster_name}-proxy"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.proxy.arn
  desired_count   = 2

  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }

  network_configuration {
    subnets          = var.private_subnets
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.proxy_target_group_arn
    container_name   = "proxy"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}

# Auto-scaling for proxy
resource "aws_appautoscaling_target" "proxy" {
  max_capacity       = 20
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.proxy.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "proxy_cpu" {
  name               = "${var.cluster_name}-proxy-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.proxy.resource_id
  scalable_dimension = aws_appautoscaling_target.proxy.scalable_dimension
  service_namespace  = aws_appautoscaling_target.proxy.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 60.0
  }
}

# ------------------------------------------------------------------ #
# Admin Service
# ------------------------------------------------------------------ #
resource "aws_ecs_task_definition" "admin" {
  family                   = "${var.cluster_name}-admin"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.exec.arn

  container_definitions = jsonencode([{
    name      = "admin"
    image     = var.admin_image
    essential = true
    portMappings = [{ containerPort = 8081, protocol = "tcp" }]

    environment = [
      { name = "ADMIN_PORT",      value = "8081" },
      { name = "MIGRATIONS_PATH", value = "/app/migrations" },
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = var.database_url },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_group
        awslogs-region        = "ap-northeast-1"
        awslogs-stream-prefix = "admin"
      }
    }
  }])
}

resource "aws_ecs_service" "admin" {
  name            = "${var.cluster_name}-admin"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.admin.arn
  desired_count   = 1

  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }

  network_configuration {
    subnets         = var.private_subnets
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = var.admin_target_group_arn
    container_name   = "admin"
    container_port   = 8081
  }
}

output "security_group_id" { value = aws_security_group.ecs.id }
output "cluster_name"      { value = aws_ecs_cluster.this.name }
