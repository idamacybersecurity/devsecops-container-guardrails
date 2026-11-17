resource "aws_sqs_queue" "security_events" {
  name                       = "${local.project_name}-security-events"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-security-events"
    Purpose = "cloud-control-plane-security-event-buffer"
  })
}

resource "aws_sqs_queue" "security_events_dlq" {
  name                       = "${local.project_name}-security-events-dlq"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 60

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-security-events-dlq"
    Purpose = "cloud-control-plane-security-event-dead-letter"
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "security_events_dlq" {
  queue_url = aws_sqs_queue.security_events_dlq.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.security_events.arn]
  })
}

resource "aws_sqs_queue_redrive_policy" "security_events" {
  queue_url = aws_sqs_queue.security_events.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.security_events_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_cloudwatch_event_rule" "security_events" {
  name           = "${local.project_name}-security-events"
  description    = "Routes CloudTrail security-sensitive API activity to the security event queue"
  event_bus_name = "default"
  state          = "ENABLED"

  event_pattern = jsonencode({
    source = [
      "aws.iam",
      "aws.cloudtrail",
      "aws.secretsmanager",
      "aws.ssm",
      "aws.ec2",
      "aws.lambda",
      "aws.sts",
      "aws.s3",
      "aws.kms"
    ]

    detail-type = [
      "AWS API Call via CloudTrail"
    ]

    detail = {
      eventSource = [
        "iam.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "secretsmanager.amazonaws.com",
        "ssm.amazonaws.com",
        "ec2.amazonaws.com",
        "lambda.amazonaws.com",
        "sts.amazonaws.com",
        "s3.amazonaws.com",
        "kms.amazonaws.com"
      ]

      eventName = [
        "PutUserPolicy",
        "PutRolePolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "CreateAccessKey",
        "UpdateAssumeRolePolicy",
        "PassRole",
        "RunInstances",
        "CreateFunction",
        "StopLogging",
        "DeleteTrail",
        "DeleteBucketPolicy",
        "DisableKeyRotation",
        "GetSecretValue",
        "GetParameters",
        "GetParametersByPath",
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        "PutBucketPolicy"
      ]
    }
  })

  tags = merge(local.common_tags, {
    Name    = "${local.project_name}-security-events"
    Purpose = "security-event-detection"
  })
}

resource "aws_cloudwatch_event_target" "security_events_sqs" {
  rule           = aws_cloudwatch_event_rule.security_events.name
  event_bus_name = "default"
  target_id      = "SecurityEventQueue"
  arn            = aws_sqs_queue.security_events.arn

  depends_on = [
    aws_sqs_queue_policy.security_events
  ]
}

resource "aws_sqs_queue_policy" "security_events" {
  queue_url = aws_sqs_queue.security_events.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AllowEventBridgeSecurityRule"
        Effect = "Allow"

        Principal = {
          Service = "events.amazonaws.com"
        }

        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.security_events.arn

        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.security_events.arn
          }
        }
      }
    ]
  })
}

output "security_event_dlq_url" {
  description = "SQS dead-letter queue URL for repeatedly failing security events"
  value       = aws_sqs_queue.security_events_dlq.url
}

output "security_event_dlq_arn" {
  description = "SQS dead-letter queue ARN"
  value       = aws_sqs_queue.security_events_dlq.arn
}

output "security_event_bus_name" {
  description = "EventBridge bus receiving CloudTrail security events"
  value       = "default"
}

output "security_event_rule_arn" {
  description = "ARN of the EventBridge security detection rule"
  value       = aws_cloudwatch_event_rule.security_events.arn
}

output "security_event_queue_url" {
  description = "SQS queue URL for the Python security detector"
  value       = aws_sqs_queue.security_events.url
}

output "security_event_queue_arn" {
  description = "SQS queue ARN for the Python security detector"
  value       = aws_sqs_queue.security_events.arn
}
