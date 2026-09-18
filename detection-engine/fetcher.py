"""Fetch VPC Flow Log records from CloudWatch Logs."""

import boto3
from datetime import datetime, timedelta
from config import AWS_REGION, LOG_GROUP_NAME


def get_cloudwatch_client():
    return boto3.client("logs", region_name=AWS_REGION)


def get_all_log_streams():
    """Get all log streams in the log group, sorted by most recent event."""
    client = get_cloudwatch_client()
    
    response = client.describe_log_streams(
        logGroupName=LOG_GROUP_NAME,
        orderBy="LastEventTime",
        descending=True,
        limit=10
    )
    
    return response.get("logStreams", [])


def fetch_stream_events(log_stream_name, limit=10000):
    """
    Fetch the most recent events from a specific log stream.
    """
    client = get_cloudwatch_client()
    
    events = []
    next_token = None
    
    while True:
        kwargs = {
            "logGroupName": LOG_GROUP_NAME,
            "logStreamName": log_stream_name,
            "limit": limit,
            "startFromHead": False,  
        }
        if next_token:
            kwargs["nextToken"] = next_token
            
        response = client.get_log_events(**kwargs)
        
        for event in response.get("events", []):
            events.append({
                "timestamp": event["timestamp"],
                "message": event["message"].strip(),
            })
            
        next_token = response.get("nextForwardToken")
        if not next_token or next_token == kwargs.get("nextToken"):
            break
            
        if len(events) >= limit:
            break
            
    return events


def fetch_recent_flow_logs(minutes_back=60):
    """
    Fetch flow log records from all active log streams.
    """
    print(f"Looking for log streams in: {LOG_GROUP_NAME}")
    
    streams = get_all_log_streams()
    if not streams:
        print("No log streams found!")
        return []
    
    all_events = []
    for stream in streams:
        stream_name = stream["logStreamName"]
        last_event_ts = stream.get("lastEventTimestamp", 0)
        
       
        if last_event_ts:
            last_event_time = datetime.utcfromtimestamp(last_event_ts / 1000).strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            last_event_time = "unknown"
            
        print(f"  Stream: {stream_name} | Last event: {last_event_time}")
        
        events = fetch_stream_events(stream_name)
        print(f"    -> Fetched {len(events)} events from this stream")
        all_events.extend(events)
    
    all_events.sort(key=lambda x: x["timestamp"])
    
    cutoff_time = int((datetime.utcnow() - timedelta(minutes=minutes_back)).timestamp() * 1000)
    recent_events = [e for e in all_events if e["timestamp"] >= cutoff_time]
    
    print(f"\nTotal events fetched: {len(all_events)}")
    print(f"Events within last {minutes_back} minutes: {len(recent_events)}")
    
    return recent_events

