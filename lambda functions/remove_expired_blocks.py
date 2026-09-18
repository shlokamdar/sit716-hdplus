import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from blocklist_utils import parse_description

ec2 = boto3.client("ec2")

TARGET_SG_ID = os.environ["TARGET_SG_ID"]


def get_auto_blocked_rules():
    response = ec2.describe_security_groups(GroupIds=[TARGET_SG_ID])
    sg = response["SecurityGroups"][0]

    matches = []
    for perm in sg.get("IpPermissions", []):
        for ip_range in perm.get("IpRanges", []):
            parsed = parse_description(ip_range.get("Description"))
            if parsed is None:
                continue  
            single_rule_perm = {
                "IpProtocol": perm["IpProtocol"],
                "IpRanges": [ip_range],
            }
            if "FromPort" in perm:
                single_rule_perm["FromPort"] = perm["FromPort"]
            if "ToPort" in perm:
                single_rule_perm["ToPort"] = perm["ToPort"]
            matches.append((single_rule_perm, parsed))

    return matches


def handler(event, context):
    now = datetime.now(timezone.utc)
    auto_blocked = get_auto_blocked_rules()

    removed = []
    still_active = []

    for ip_permission, tag in auto_blocked:
        cidr = ip_permission["IpRanges"][0]["CidrIp"]
        if tag["expiry"] <= now:
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=TARGET_SG_ID,
                    IpPermissions=[ip_permission],
                )
                removed.append(cidr)
                print(f"REMOVED expired block: {cidr} (expired {tag['expiry'].isoformat()})")
            except ClientError as e:
                print(f"ERROR removing block {cidr}: {e}")
        else:
            still_active.append(cidr)

    print(f"Swept {len(auto_blocked)} auto-blocked rule(s): "
          f"{len(removed)} removed, {len(still_active)} still active.")

    return {
        "statusCode": 200,
        "body": {
            "removed": removed,
            "still_active": still_active,
        },
    }
