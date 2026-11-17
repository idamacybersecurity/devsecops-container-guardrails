resource "aws_secretsmanager_secret" "application_config" {
  name        = "${local.project_name}/application-config"
  description = "Application configuration secret for the cloud control plane security lab"

  kms_key_id = aws_kms_key.audit.arn

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-application-config"
    Purpose = "encrypted-application-configuration"
  })
}

output "application_config_secret_arn" {
  description = "ARN of the KMS-encrypted application configuration secret"
  value       = aws_secretsmanager_secret.application_config.arn
}
