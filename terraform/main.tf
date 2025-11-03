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
  lifecycle = {
    prevent_destroy = true
  }

}

resource "aws_cloudtrail" "main" {
  name =                                     "ctd-trail"
  s3_bucket_name =                           aws_s3_bucket.cloudtrail_logs.id
  include_global_services_events =           true
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
