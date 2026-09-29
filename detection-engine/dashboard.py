import json
import os
from datetime import datetime, timezone

import boto3

from blocklist_utils import parse_description
from config import AWS_REGION
from timezone_utils import utc_str_to_ist, utc_dt_to_ist

TARGET_SG_NAME = "target-sg"


def load_last_n_alerts(alerts_file, n=5):
    if not os.path.exists(alerts_file):
        return []
    with open(alerts_file, "r") as f:
        lines = [line for line in f if line.strip()]
    alerts = [json.loads(line) for line in lines[-n:]]
    for a in alerts:
        a["timestamp"] = utc_str_to_ist(a["timestamp"])
    return alerts


def load_active_blocks():
    """
    Query the live Target Security Group for IDS-managed block state.

    The Security Group stores:
      - blocked IP
      - expiry
      - reason
      - NACL rule number

    The NACL is the actual enforcement layer.
    """

    try:
        ec2 = boto3.client(
            "ec2",
            region_name=AWS_REGION
        )

        response = ec2.describe_security_groups(
            Filters=[
                {
                    "Name": "group-name",
                    "Values": [TARGET_SG_NAME]
                }
            ]
        )

        security_groups = response.get(
            "SecurityGroups",
            []
        )

        if not security_groups:
            return []

        sg = security_groups[0]

        now = datetime.now(timezone.utc)

        active = []

        for perm in sg.get("IpPermissions", []):

            for ip_range in perm.get("IpRanges", []):

                parsed = parse_description(
                    ip_range.get("Description")
                )

                if parsed is None:
                    continue

                if parsed["expiry"] <= now:
                    continue

                active.append({
                    "ip": ip_range["CidrIp"],
                    "expiry": utc_dt_to_ist(
                        parsed["expiry"]
                    ),
                    "reason": parsed["reason"],
                    "nacl_rule": parsed.get("nacl_rule"),
                    "enforcement": (
                        "NACL DENY"
                        if parsed.get("nacl_rule") is not None
                        else "SG"
                    ),
                })

        return active

    except Exception as e:

        print(
            f"  [dashboard] could not query active blocks: {e}"
        )

        return []

def print_dashboard(alerts_file="alerts.jsonl", baseline_file="baseline_profile.json"):
    print("\n" + "=" * 70)
    print("IDS DASHBOARD".center(70))
    print("=" * 70)

    # --- Last 5 alerts ---
    print("\nLAST 5 ALERTS")
    print("-" * 70)
    alerts = load_last_n_alerts(alerts_file, 5)
    if not alerts:
        print("  (no alerts yet)")
    else:
        for a in alerts:
            print(f"  [{a['timestamp']}] {a['src_ip']:16} {a['alert_type']:20} "
                  f"{a['severity']:6} via {a['triggering_method']}")

    # --- Active blocks ---
    print("\nACTIVE BLOCKS")
    print("-" * 70)
    blocks = load_active_blocks()
    if not blocks:
        print("  (none currently active)")
    else:
        for b in blocks:
            print(
                    f"  {b['ip']:16} "
                    f"expires {b['expiry']}  "
                    f"reason={b['reason']}  "
                    f"enforcement={b['enforcement']} "
                    f"rule={b.get('nacl_rule', '-')}"
            )

    # --- Baseline summary ---
    print("\nBASELINE STATISTICS SUMMARY")
    print("-" * 70)
    if os.path.exists(baseline_file):
        with open(baseline_file, "r") as f:
            baseline = json.load(f)
        for feature, stats in baseline.items():
            print(f"  {feature:24} mean={stats['mean']:.3f}  std={stats['std']:.3f}")
    else:
        print("  (no baseline profile found)")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    print_dashboard()
