resource "aws_iam_role" "developer" {
  name        = "${local.project_name}-developer"
  description = "Developer entry role for the controlled CI/CD assumption chain"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowLabAccountBootstrap"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.localstack.account_id}:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "cloud-control-plane-defense-developer-entry"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-developer"
    Role = "developer"
  })
}

resource "aws_iam_role" "cicd" {
  name        = "${local.project_name}-cicd"
  description = "CI/CD role assumable only by the developer role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TrustDeveloperRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.developer.arn
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-cicd"
    Role = "cicd"
  })
}

resource "aws_iam_role" "production" {
  name        = "${local.project_name}-production"
  description = "Production application role assumable only by the CI/CD role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TrustCICDRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.cicd.arn
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-production"
    Role = "production"
  })
}

resource "aws_iam_role_policy" "developer_assume_cicd" {
  name = "${local.project_name}-developer-assume-cicd"
  role = aws_iam_role.developer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = aws_iam_role.cicd.arn
    }]
  })
}

resource "aws_iam_role_policy" "cicd_assume_production" {
  name = "${local.project_name}-cicd-assume-production"
  role = aws_iam_role.cicd.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = aws_iam_role.production.arn
    }]
  })
}

resource "aws_iam_role_policy" "production_secret_access" {
  name = "${local.project_name}-production-secret-access"
  role = aws_iam_role.production.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadApplicationConfiguration"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.application_config.arn
      },
      {
        Sid      = "DecryptApplicationConfiguration"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.audit.arn
      }
    ]
  })
}

output "developer_role_arn" {
  description = "Developer entry role ARN"
  value       = aws_iam_role.developer.arn
}

output "cicd_role_arn" {
  description = "CI/CD role ARN"
  value       = aws_iam_role.cicd.arn
}

output "production_role_arn" {
  description = "Production role ARN"
  value       = aws_iam_role.production.arn
}
