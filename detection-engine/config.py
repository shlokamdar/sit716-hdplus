
"""Configuration for the IDS detection engine."""

AWS_REGION = "ap-south-1"
LOG_GROUP_NAME = "/aws/vpc/ids-flow-logs"

# Time window for aggregation (seconds)
WINDOW_SIZE = 60
FLOW_LOG_FIELDS = [
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
]