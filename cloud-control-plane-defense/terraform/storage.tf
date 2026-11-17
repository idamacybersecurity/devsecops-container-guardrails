resource "aws_kms_key" "audit" {
  description             = "KMS key for cloud control plane audit and forensic storage"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-audit-key"
    Purpose = "audit-and-forensics"
  })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/cloud-control-plane-defense-audit"
  target_key_id = aws_kms_key.audit.key_id
}

resource "aws_s3_bucket" "audit" {
  bucket        = "cloud-control-plane-defense-audit"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-audit"
    Purpose = "cloudtrail-audit-logs"
  })
}

resource "aws_s3_bucket" "forensics" {
  bucket        = "cloud-control-plane-defense-forensics"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-forensics"
    Purpose = "security-forensic-snapshots"
  })
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    blocked_encryption_types = ["SSE-C"]

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    blocked_encryption_types = ["SSE-C"]

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }

    bucket_key_enabled = true
  }
}

output "audit_kms_key_arn" {
  description = "KMS key ARN used for audit and forensic storage"
  value       = aws_kms_key.audit.arn
}

output "audit_bucket_name" {
  description = "Private S3 bucket for CloudTrail audit records"
  value       = aws_s3_bucket.audit.id
}

output "forensics_bucket_name" {
  description = "Private S3 bucket for forensic snapshots"
  value       = aws_s3_bucket.forensics.id
}
