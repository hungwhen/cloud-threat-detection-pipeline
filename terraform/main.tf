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
    prevent_destroy = false
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
    prevent_destroy = false
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

        # Glue Data Catalog (Athena needs this)
    {
      Effect = "Allow"
      Action = [
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartition",
        "glue:GetPartitions"
      ]
      Resource = [
        "arn:aws:glue:${var.region}:${var.account_id}:catalog",
        "arn:aws:glue:${var.region}:${var.account_id}:database/${aws_athena_database.cloudtrail_db.name}",
        "arn:aws:glue:${var.region}:${var.account_id}:table/${aws_athena_database.cloudtrail_db.name}/*"
      ]
    },


        # S3 buckets (CloudTrail logs + Athena results)
    {
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      Resource = [
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

resource "aws_lambda_function" "detection" {
  function_name = "ctd-detection"
  role = aws_iam_role.lambda_detection_role.arn
  runtime = "python3.11"
  handler = "lambda_function.handler"

  filename         = "../lambdas/build/ctd_detection.zip"
  source_code_hash = filebase64sha256("../lambdas/build/ctd_detection.zip")


  timeout = 60

  environment {
    variables = {
      ATHENA_DB_NAME = aws_athena_database.cloudtrail_db.name
      ATHENA_WORKGROUP = aws_athena_workgroup.ctd.name
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      CLOUDTRAIL_S3_BUCKET = aws_s3_bucket.cloudtrail_logs.bucket
    }
  }

}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {

  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Statement = [
      {
        Sid = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid = "AWSCloudTrailWrite"
        Effect = "Allow" 
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${var.account_id}/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "ctd_schedule" {
  name = "ctd-detection-schedule"
  schedule_expression = "rate(5 minutes)" # or cron()
}

resource "aws_cloudwatch_event_target" "ctd_lambda_target" {
  rule = aws_cloudwatch_event_rule.ctd_schedule.name
  target_id = "ctd-lambda"
  arn = aws_lambda_function.detection.arn
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id = "AllowExecutionFromEventBridge"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection.function_name
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.ctd_schedule.arn
}

resource "aws_athena_workgroup" "ctd" {
  name = "ctd_workgroup"
  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
    }
    enforce_workgroup_configuration = true
  }
  state = "ENABLED"

  force_destroy = true

}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_athena_database.cloudtrail_db.name
  table_type    = "EXTERNAL_TABLE"

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.cloudtrail_logs.bucket}/AWSLogs/${var.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    columns {
      name = "eventVersion"
      type = "string"
    }
    columns {
      name = "userIdentity"
      type = "struct<type:string,principalId:string,arn:string,accountId:string,invokedBy:string,accessKeyId:string,userName:string,sessionContext:struct<attributes:struct<mfaAuthenticated:string,creationDate:string>,sessionIssuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"
    }
    columns {
      name = "eventTime"
      type = "string"
    }
    columns {
      name = "eventSource"
      type = "string"
    }
    columns {
      name = "eventName"
      type = "string"
    }
    columns {
      name = "awsRegion"
      type = "string"
    }
    columns {
      name = "sourceIPAddress"
      type = "string"
    }
    columns {
      name = "userAgent"
      type = "string"
    }
    columns {
      name = "errorCode"
      type = "string"
    }
    columns {
      name = "errorMessage"
      type = "string"
    }
    columns {
      name = "requestParameters"
      type = "string"
    }
    columns {
      name = "responseElements"
      type = "string"
    }
    columns {
      name = "additionalEventData"
      type = "string"
    }
    columns {
      name = "requestID"
      type = "string"
    }
    columns {
      name = "eventID"
      type = "string"
    }
    columns {
      name = "readOnly"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountId:string,type:string>>"
    }
    columns {
      name = "eventType"
      type = "string"
    }
    columns {
      name = "apiVersion"
      type = "string"
    }
    columns {
      name = "recipientAccountId"
      type = "string"
    }
    columns {
      name = "serviceEventDetails"
      type = "string"
    }
    columns {
      name = "sharedEventID"
      type = "string"
    }
    columns {
      name = "vpcEndpointId"
      type = "string"
    }
  }

  parameters = {
    classification = "cloudtrail"
  }
}






resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}  

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
