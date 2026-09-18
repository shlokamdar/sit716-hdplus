"""Parse raw VPC Flow Log records into structured dictionaries."""

from config import FLOW_LOG_FIELDS


def parse_flow_log_record(raw_message):
    parts = raw_message.split()
    
    if len(parts) != len(FLOW_LOG_FIELDS):
        return None
        
    record = {}
    for i, field_name in enumerate(FLOW_LOG_FIELDS):
        value = parts[i]
        
        if field_name in ["version", "packets", "bytes", "start", "end"]:
            try:
                value = int(value)
            except ValueError:
                value = 0
        elif field_name in ["srcport", "dstport", "protocol"]:
            try:
                value = int(value)
            except ValueError:
                value = None
                
        record[field_name] = value
        
    return record


def parse_all_records(raw_events):
    parsed = []
    for event in raw_events:
        record = parse_flow_log_record(event["message"])
        if record:
            record["_ingestion_timestamp"] = event["timestamp"]
            parsed.append(record)
    return parsed