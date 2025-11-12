import os
import json
import boto3 #amazon python SDK
import time

ATHENA = boto3.client("athena")
SNS = boto3.client("sns")

#------- env variables ------

ATHENA_DB_NAME = os.environ["ATHENA_DB_NAME"]
ATHENA_WORKGROUP = os.environ["ATHENA_WORKGROUP"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

#------ sussy actions --

SUSPICIOUS_ACTIONS = [
  # privilege esc
  "CreateUser",
  "AttachUserPolicy",
  "PutUserPolicy",
  "AddUserToGroup",
  "CreateAccessKey",
  "UpdateAssumeRolePolicy",

  # data gathering and exfil
  "GetObject",
  "GetBucketAcl",
  "GetBucketPolicy",
  "ListBuckets",
  "GetParameter",

  # log tamper and defense evasion

  "StopLogging",
  "DeleteTrail",
  "UpdateTrail",
  "PutBucketPolicy"
  
]
