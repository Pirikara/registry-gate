variable "images" {
  type        = list(string)
  description = "List of image names to create repositories for"
}

variable "prefix" {
  type    = string
  default = "registory-gate"
}

resource "aws_ecr_repository" "this" {
  for_each = toset(var.images)

  name                 = "${var.prefix}/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 20 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

output "repo_urls" {
  value = { for k, v in aws_ecr_repository.this : k => v.repository_url }
}
