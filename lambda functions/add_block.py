import os
import boto3
from botocore.exceptions import ClientError

from blocklist_utils import build_description, compute_expiry, is_whitelisted

ec2 = boto3.client("ec2")

TARGET_SG_ID = os.environ["TARGET_SG_ID"]
WHITELIST_CIDRS = [c.strip() for c in os.environ.get("WHITELIST_CIDRS", "").split(",") if c.strip()]

DEFAULT_DURATION_MINUTES = 15


def handler(event, context):
    ip = event.get("ip")
    duration_minutes = event.get("duration_minutes", DEFAULT_DURATION_MINUTES)
    reason = event.get("reason", "unspecified")

    if not ip:
        return {"statusCode": 400, "body": "Missing required field: ip"}

    if is_whitelisted(ip, WHITELIST_CIDRS):
        print(f"SKIPPED: {ip} is whitelisted (management IP or AWS metadata service). Not blocking.")
        return {"statusCode": 200, "body": f"Skipped whitelisted IP {ip}"}

    blocked_at, expiry = compute_expiry(duration_minutes)
    description = build_description(blocked_at, expiry, reason)

    try:
        ec2.authorize_security_group_ingress(
            GroupId=TARGET_SG_ID,
            IpPermissions=[
                {
                    "IpProtocol": "-1",  # all protocols
                    "IpRanges": [
                        {
                            "CidrIp": f"{ip}/32",
                            "Description": description,
                        }
                    ],
                }
            ],
        )
        print(f"BLOCKED: {ip} until {expiry.isoformat()} (reason={reason})")
        return {
            "statusCode": 200,
            "body": {
                "ip": ip,
                "blocked_at": blocked_at.isoformat(),
                "expiry": expiry.isoformat(),
                "reason": reason,
            },
        }

    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
            print(f"ALREADY BLOCKED: {ip} — rule already exists, skipping.")
            return {"statusCode": 200, "body": f"{ip} already blocked"}
        print(f"ERROR blocking {ip}: {e}")
        raise
