import os
import boto3
from botocore.exceptions import ClientError

from blocklist_utils import (
    NACL_RULE_BASE,
    NACL_RULE_MAX,
    build_description,
    compute_expiry,
    is_whitelisted,
)

ec2 = boto3.client("ec2")

TARGET_SG_ID = os.environ["TARGET_SG_ID"]
TARGET_NACL_ID = os.environ["TARGET_NACL_ID"]
WHITELIST_CIDRS = [c.strip() for c in os.environ.get("WHITELIST_CIDRS", "").split(",") if c.strip()]

DEFAULT_DURATION_MINUTES = 15


def get_nacl_entries():
    """Return all ingress entries of the target NACL as (rule_number, cidr, action)."""
    response = ec2.describe_network_acls(NetworkAclIds=[TARGET_NACL_ID])
    entries = []
    for entry in response["NetworkAcls"][0].get("Entries", []):
        if entry.get("Egress"):
            continue
        entries.append((entry["RuleNumber"], entry.get("CidrBlock"), entry["RuleAction"]))
    return entries


def find_managed_nacl_rule(cidr):
    """Return the rule number of an existing managed DENY entry for cidr, if any."""
    for rule_number, entry_cidr, action in get_nacl_entries():
        if entry_cidr == cidr and action == "deny" and NACL_RULE_BASE <= rule_number <= NACL_RULE_MAX:
            return rule_number
    return None


def allocate_nacl_rule_number():
    """Smallest free rule number in the managed range."""
    used = {n for n, _, _ in get_nacl_entries()}
    for n in range(NACL_RULE_BASE, NACL_RULE_MAX + 1):
        if n not in used:
            return n
    raise RuntimeError(f"No free NACL rule numbers in managed range {NACL_RULE_BASE}-{NACL_RULE_MAX}")


def add_nacl_deny(cidr):
    """Create (or reuse) a DENY-ALL ingress entry for cidr. Returns the rule number."""
    existing = find_managed_nacl_rule(cidr)
    if existing is not None:
        print(f"NACL deny for {cidr} already exists at rule {existing}; reusing.")
        return existing

    rule_number = allocate_nacl_rule_number()
    ec2.create_network_acl_entry(
        NetworkAclId=TARGET_NACL_ID,
        RuleNumber=rule_number,
        Protocol="-1",         
        RuleAction="deny",
        Egress=False,
        CidrBlock=cidr,
    )
    print(f"NACL DENY added: {cidr} at ingress rule {rule_number}")
    return rule_number


def delete_nacl_entry(rule_number):
    try:
        ec2.delete_network_acl_entry(
            NetworkAclId=TARGET_NACL_ID,
            RuleNumber=rule_number,
            Egress=False,
        )
        print(f"NACL entry {rule_number} deleted (rollback).")
        return True
    except ClientError as e:
        print(f"Rollback warning: could not delete NACL entry {rule_number}: {e}")
        return False


def handler(event, context):
    ip = event.get("ip")
    duration_minutes = event.get("duration_minutes", DEFAULT_DURATION_MINUTES)
    reason = event.get("reason", "unspecified")

    if not ip:
        return {"statusCode": 400, "body": "Missing required field: ip"}

    if is_whitelisted(ip, WHITELIST_CIDRS):
        print(f"SKIPPED: {ip} is whitelisted (management IP or AWS metadata service). Not blocking.")
        return {"statusCode": 200, "body": f"Skipped whitelisted IP {ip}"}

    cidr = f"{ip}/32"
    blocked_at, expiry = compute_expiry(duration_minutes)
    nacl_rule = None

    try:
        nacl_rule = add_nacl_deny(cidr)
        description = build_description(blocked_at, expiry, reason, nacl_rule=nacl_rule)
        ec2.authorize_security_group_ingress(
            GroupId=TARGET_SG_ID,
            IpPermissions=[
                {
                    "IpProtocol": "-1",  # all protocols
                    "IpRanges": [{"CidrIp": cidr, "Description": description}],
                }
            ],
        )
        print(f"BLOCKED: {ip} until {expiry.isoformat()} "
              f"(reason={reason}, nacl_rule={nacl_rule})")
        return {
            "statusCode": 200,
            "body": {
                "ip": ip,
                "blocked_at": blocked_at.isoformat(),
                "expiry": expiry.isoformat(),
                "reason": reason,
                "nacl_rule": nacl_rule,
                "enforcement": "nacl-deny",
            },
        }

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidPermission.Duplicate":
            if nacl_rule is None:
                nacl_rule = find_managed_nacl_rule(cidr)
            print(f"ALREADY BLOCKED: {ip} — rule already exists, skipping.")
            return {"statusCode": 200, "body": f"{ip} already blocked"}
        if nacl_rule is not None:
            delete_nacl_entry(nacl_rule)
        print(f"ERROR blocking {ip}: {e}")
        raise
