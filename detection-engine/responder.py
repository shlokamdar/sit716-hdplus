import json
import os

import boto3

from config import AWS_REGION

ADD_BLOCK_FUNCTION_NAME = os.environ.get("ADD_BLOCK_FUNCTION_NAME", "ids-add-block")
DEFAULT_BLOCK_DURATION_MINUTES = 15

_lambda_client = None


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=AWS_REGION)
    return _lambda_client


def invoke_add_block(src_ip, reason, duration_minutes=DEFAULT_BLOCK_DURATION_MINUTES):
    payload = {
        "ip": src_ip,
        "duration_minutes": duration_minutes,
        "reason": reason,
    }
    try:
        response = _get_lambda_client().invoke(
            FunctionName=ADD_BLOCK_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        raw_body = response["Payload"].read()
        result = json.loads(raw_body)
        
        function_status = result.get("statusCode")
        if function_status == 200:
            print(f"  [respond] add-block confirmed for {src_ip} (reason={reason}): {result.get('body')}")
            return True
        else:
            print(f"  [respond] add-block returned non-200 for {src_ip} (reason={reason}): {result}")
            return False

    except Exception as e:
        print(f"  [respond] FAILED to invoke add-block for {src_ip}: {e}")
        return False
