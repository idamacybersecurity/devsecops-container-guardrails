terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.35.1"
    }
  }
}

provider "aws" {
  region     = "eu-north-1"
  access_key = "test"
  secret_key = "test"

  skip_credentials_validation = true
  skip_metadata_api_check     = true

  s3_use_path_style = true

  endpoints {
    iam            = "http://127.0.0.1:4566"
    sts            = "http://127.0.0.1:4566"
    ec2            = "http://127.0.0.1:4566"
    s3             = "http://127.0.0.1:4566"
    s3control      = "http://localhost.localstack.cloud:4566"
    kms            = "http://127.0.0.1:4566"
    secretsmanager = "http://127.0.0.1:4566"
    cloudtrail     = "http://127.0.0.1:4566"
    events         = "http://127.0.0.1:4566"
    sqs            = "http://127.0.0.1:4566"
  }
}

data "aws_caller_identity" "localstack" {}

output "connected_account_id" {
  value = data.aws_caller_identity.localstack.account_id
}

output "connected_arn" {
  value = data.aws_caller_identity.localstack.arn
}
