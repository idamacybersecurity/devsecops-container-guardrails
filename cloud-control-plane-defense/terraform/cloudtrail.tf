resource "aws_cloudtrail" "main" {
  name                          = "${local.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  kms_key_id                    = aws_kms_key.audit.arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true

  depends_on = [
    aws_s3_bucket_policy.audit_cloudtrail,
    aws_kms_key_policy.audit_cloudtrail
  ]

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-trail"
    Purpose = "cloud-control-plane-audit"
  })
}

output "cloudtrail_arn" {
  description = "ARN of the multi-Region CloudTrail audit trail"
  value       = aws_cloudtrail.main.id
}
