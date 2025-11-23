import os
import json
import boto3 #amazon python SDK
import time

from typing import List, Dict, Any

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
    action_list = ",".join(f"'{x}'" for x in SUSPICIOUS_ACTIONS)
    query = f"""
    SELECT
      eventtime,
      eventname,
      useridentity.userName    AS username,
      useridentity.arn         AS user_arn,
      sourceipaddress,
      awsregion
    FROM cloudtrail_logs
    WHERE eventname IN ({action_list})
      AND from_iso8601_timestamp(eventtime)
            > current_timestamp - interval '{lookback_minutes}' minute
    ORDER BY eventtime DESC
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

def fetch_query_results(execution_id: str) -> List[Dict[str, Any]]:
  results = ATHENA.get_query_results(QueryExecutionId=execution_id)
  rows = results.get("ResultSet", {}).get("Rows", [])

  data_rows = rows[1:] if len(rows) > 1 else []
  print(f"[INFORMATION] Retrieved {len(data_rows)} data rows from Athena.")
  return data_rows

def parse_rows_to_events(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for row in rows:
        cols = row.get("Data", [])
        values = [c.get("VarCharValue", "") for c in cols]

        event = {
            "eventTime":   values[0] if len(values) > 0 else "",
            "eventName":   values[1] if len(values) > 1 else "",
            "userIdentity": values[2] if len(values) > 2 else "",  # username
            # values[3] is the user_arn (optional)
            "sourceIP":    values[4] if len(values) > 4 else "",
            "region":      values[5] if len(values) > 5 else "",
        }

        events.append(event)

    return events



def build_alert_message(events: List[Dict[str, Any]]) -> str:

  payload = {
    "summary": f"{len(events)} suspicious cloudtrail events detected",
    "findings": events,
    "mitre mapping": {
      "Privilege Escalation": "T1078 / T1098",
      "Data Exfiltration" : "T1537 / T1041",
      "Defense Evasion" : "T1562",
    },
  }
  msg_str = json.dumps(payload, indent=2)
  print("[DEBUG] Alert payload:")
  print(msg_str)
  return msg_str

def publish_sns_alert(message: str) -> None:

  print("[INFORMATION] pushing alert to SNS...")

  SNS.publish(
    TopicArn=SNS_TOPIC_ARN,
    Subject="[CTD] CloudTrail Threat Detection Alert",
    Message = message,
  )

  print("[INFORMATION] sns alert published")

def handler(event, context):

  print("[INFORMATION] lambda is starting... python is RUNNING")
  query = build_detection_query(lookback_minutes=10)
  execution_id = start_athena_query(query)

  try:
    wait_for_query(execution_id)
  except RuntimeError as e:
    return {"status code" : 500, "body": str(e)}

  rows = fetch_query_results(execution_id)
  if not rows:
    print("[INFORMATION] nothing sus was found lol")
    return {"status code": 200, "body": "nothing sus was found"}

  events = parse_rows_to_events(rows)
  message = build_alert_message(events)
  publish_sns_alert(message)

  return {
    "status code" : 200,
    "body": f"Alert sent: {len(events)} findings",
  }

