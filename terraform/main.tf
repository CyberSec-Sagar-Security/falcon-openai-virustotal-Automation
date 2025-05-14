terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Lambda function for alert processing
resource "aws_lambda_function" "alert_processor" {
  filename         = "../dist/lambda.zip"
  function_name    = "security-alert-processor"
  role            = aws_iam_role.lambda_role.arn
  handler         = "main.lambda_handler"
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      CONFIG_BUCKET = aws_s3_bucket.config_bucket.id
      CONFIG_KEY    = "config.json"
    }
  }
}

# S3 bucket for configuration
resource "aws_s3_bucket" "config_bucket" {
  bucket = "security-alert-config-${var.environment}"
}

# SQS queue for alerts
resource "aws_sqs_queue" "alert_queue" {
  name                      = "security-alerts-queue"
  delay_seconds             = 0
  max_message_size         = 262144
  message_retention_seconds = 86400
  visibility_timeout_seconds = 300
}

# IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "security-alert-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for Lambda
resource "aws_iam_role_policy" "lambda_policy" {
  name = "security-alert-processor-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.alert_queue.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.config_bucket.arn}/*"
      }
    ]
  })
}

# Variables
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name (e.g., dev, prod)"
  type        = string
  default     = "dev"
}

# Outputs
output "lambda_function_name" {
  value = aws_lambda_function.alert_processor.function_name
}

output "sqs_queue_url" {
  value = aws_sqs_queue.alert_queue.url
}

output "config_bucket_name" {
  value = aws_s3_bucket.config_bucket.id
}
