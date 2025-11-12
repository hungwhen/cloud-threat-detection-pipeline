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

def build_detection_query(lookback_minutes: int = 10) -> str:
  # BUILD UP THE ATEHNA SQL QUERY

  action_list = ",".join(f"'{x}'" for x in SUSPICIOUS_ACTIONS)
  query = f"""
  SELECT eventtime, useridentity, eventname, sourceipaddress, awsregion
  FROM cloudtrail_logs
  WHERE eventname IN ({action_list})
    AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '{lookback_minutes}' minute
  """
  return query

def start_athena_query(query : str) -> str:
  #start athena query
  resp = ATHENA.start_query_execution(
    QueryString=query,
    QueryExecutionContext={"Database": ATHENA_DB_NAME},
    WorkGroup=ATHENA_WORKGROUP,
  )

  execution_id = resp["QueryExecutionId"]
  print(f"[INFORMATION] Started Athena Query Execution ID:{execution_id}")
  return execution_id

def wait_for_query(execution_id: str, poll_interval: int = 3) -> Dict[str,Any]:
  #poll athena until the query finishes. return response or raise error if query fails.

  state = "RUNNING"
  last_resp = {}

  while state in ("RUNNING", "QUEUED"):
    time.sleep(poll_interval)
    last_resp = ATHENA.get_query_execution(QueryExecutionId=execution_id)
    state = last_resp["QueryExecution"]["Status"]["State"]
    print(f"[DEBUGGING] query state for {execution_id}: {state}")

  if state != "SUCCEEDED":
    reason = last_resp["QueryExecution"]["Status"].get(
      "StateChangeReason", "Unknown"
    )
    print(f"[ERROR] Athena query FAILED LMAO: {reason}")
    raise RuntimeError(f"Athena query failed LMAO: {reason}")

  return last_resp

