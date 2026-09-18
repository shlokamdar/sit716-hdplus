import json
import os

STATE_FILE = "alert_state.json"
COOLDOWN_SECONDS = 300  # 5 minutes

SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2}


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def should_alert(state, src_ip, event_ts, new_severity):
    prev = state.get(src_ip)
    if prev is None:
        return True

    time_since_last = event_ts - prev["last_alert_ts"]
    if time_since_last >= COOLDOWN_SECONDS:
        return True

    if SEVERITY_RANK.get(new_severity, 0) > SEVERITY_RANK.get(prev["last_severity"], 0):
        return True

    return False


def record_alert(state, src_ip, event_ts, severity):
    prev = state.get(src_ip)
    if prev and SEVERITY_RANK.get(prev["last_severity"], 0) > SEVERITY_RANK.get(severity, 0):
        severity = prev["last_severity"]
    state[src_ip] = {"last_alert_ts": event_ts, "last_severity": severity}
