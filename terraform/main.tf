#background environment stuff

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.4.0"
}

provider "aws" {
  region = var.region
  // profile = var.aws_profile
}

// resource - resource type - resource name

resource "aws_s3_bucket" "cloudtrail_logs" {

  bucket = "ctd-cloudtrail-logs-${var.account_id}-${var.region}" // name
  acl = "private" // no public read/write (only me access)
  force_destroy = false // no delete if theres objects in the bucket...

  // more anti deletion
  lifecycle {
    prevent_destroy = true
  }

}

resource "aws_cloudtrail" "main" {
  name =                                     "ctd-trail"
  s3_bucket_name =                           aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events =           true
  is_multi_region_trail =                    true
  enable_log_file_validation =               true
}

resource "aws_sns_topic" "alerts" {
  name = "ctd-alerts-${var.account_id}"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol = "email"
  endpoint = var.alert_email
}

resource "aws_s3_bucket" "athena_results" {

  bucket = "ctd-athena-results-${var.account_id}-${var.region}"
  acl = "private"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_athena_database" "cloudtrail_db" {

  name = "ctd_cloudtrail_db"
  bucket = aws_s3_bucket.athena_results.bucket

}


resource "aws_iam_role" "lambda_detection_role" {

  name = "ctd-lambda-detection-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {Service = "lambda.amazonaws.com"}
    }]
  })

}

resource "aws_iam_role_policy" "lambda_detection_policy" {
  name = "ctd-lambda-detection-policy"
  role = aws_iam_role.lambda_detection_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
    #Athena 
    {
      Effect = "Allow"
      Action = [
        "athena:StartQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults"
      ]
    Resource = "*"
    },
    #S3 buckets
    {
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource =  [
        aws_s3_bucket.cloudtrail_logs.arn,
        "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        aws_s3_bucket.athena_results.arn,
        "${aws_s3_bucket.athena_results.arn}/*"
      ]
    },

    # SNS alerts
    {
      Effect = "Allow"
      Action = ["sns:Publish"]
      Resource = aws_sns_topic.alerts.arn
    },

    #Cloudwatch logging

    {
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:${var.region}:${var.account_id}:*"
    }

    ]
  })

}
