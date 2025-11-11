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

resource "aws_lambda_function" "detection" {
  function_name = "ctd-detection"
  role = aws_iam_role.lambda_detection
  runtime = "python3.11"
  handler = "lambda_function.handler"

  filename = "build/ctd_detection.zip" # could be s3_bucket + s3_key
  source_code_hash = filebase64sha256("build/ctd_detection.zip")

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
  arn = aws_lambda_function.detetion.arn
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
}


resource "aws_glue_catalog_database" "ctd" {
  name = aws_athena_database.cloudtrail_db.name
}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.ctd.name

  table_type = "EXTERNAL_TABLE"

  storage_descriptor {
    location = "s3://${aws_s3_bucket.cloudtrail_logs.bucket}/AWSLogs/${var.account_id}/CloudTrail/"
    input_format = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    serde_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns = [
      { name = "eventversion", type = "string" },
      { name = "useridentity", type = "string" },
      { name = "eventtime",    type = "string" },
      { name = "eventsource",  type = "string" },
      { name = "eventname",    type = "string" },
      { name = "awsregion",    type = "string" },
      { name = "sourceipaddress", type = "string" },
      { name = "useragent",    type = "string" },
      { name = "errorcode",    type = "string" },
      { name = "requestparameters", type = "string" },
      { name = "responseelements",  type = "string" },
      { name = "additionaldata",    type = "string" },
      { name = "resources",         type = "string" },
      { name = "eventid",           type = "string" },
      { name = "eventtype",         type = "string" },
      { name = "apiversion",        type = "string" },
      { name = "readonly",          type = "string" },
      { name = "recipientaccountid", type = "string" },
      { name = "serviceeventdetails", type = "string" },
      { name = "sharedeventid",       type = "string" },
      { name = "vpcendpointid",       type = "string" }
    ]
    
  }
  parameters = {
    "classification" = "json"
  }
}
