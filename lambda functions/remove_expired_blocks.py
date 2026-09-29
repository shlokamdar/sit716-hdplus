import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from blocklist_utils import NACL_RULE_BASE, NACL_RULE_MAX, parse_description

ec2 = boto3.client("ec2")

TARGET_SG_ID = os.environ["TARGET_SG_ID"]
TARGET_NACL_ID = os.environ["TARGET_NACL_ID"]


def get_auto_blocked_rules():
    """SG rules carrying our auto-block tag (state store)."""
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


def delete_nacl_entry(rule_number):
    """Delete a deny entry from the target NACL. Returns True if gone."""
    try:
        ec2.delete_network_acl_entry(
            NetworkAclId=TARGET_NACL_ID,
            RuleNumber=rule_number,
            Egress=False,
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidNetworkAclEntry.NotFound":
            return True 
        print(f"ERROR deleting NACL entry {rule_number}: {e}")
        return False


def handler(event, context):
    now = datetime.now(timezone.utc)
    auto_blocked = get_auto_blocked_rules()

    removed = []
    still_active = []

    for ip_permission, tag in auto_blocked:
        cidr = ip_permission["IpRanges"][0]["CidrIp"]
        if tag["expiry"] <= now:
            nacl_removed = True
            nacl_rule = tag.get("nacl_rule")
            if nacl_rule is not None and NACL_RULE_BASE <= nacl_rule <= NACL_RULE_MAX:
                nacl_removed = delete_nacl_entry(nacl_rule)

        
            sg_removed = False
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=TARGET_SG_ID,
                    IpPermissions=[ip_permission],
                )
                sg_removed = True
            except ClientError as e:
                print(f"ERROR removing SG block {cidr}: {e}")

            if nacl_removed and sg_removed:
                removed.append(cidr)
                print(f"REMOVED expired block: {cidr} "
                      f"(expired {tag['expiry'].isoformat()}, nacl_rule={nacl_rule})")
            else:
                still_active.append(cidr)
                print(f"PARTIAL removal for {cidr}: nacl_removed={nacl_removed}, "
                      f"sg_removed={sg_removed}; will retry next sweep.")
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
