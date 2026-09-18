import json
import statistics
import math
from datetime import datetime
from collections import defaultdict


FEATURES_FILE = "features_20260824_132034.json"  # <-- features file
BASELINE_FILE = "baseline_profile.json"
ALERTS_FILE   = "alerts.jsonl"
Z_THRESHOLD   = 4.0          
MIN_STD_FLOOR = 0.01        

ZSCORE_FEATURES = [
    "total_connections",
    "unique_dst_ports",
    "avg_packets_per_conn",
    "avg_bytes_per_conn",
    "connections_per_second",
    "reject_ratio",
    "total_packets",
    "total_bytes",
    "avg_duration_seconds"
]

LOG_TRANSFORM_FEATURES = {
    "avg_packets_per_conn",
    "avg_bytes_per_conn",
    "total_packets",
    "total_bytes",
}


def transform_value(feature, value):
    """Apply log1p to heavy-tailed volume features; pass everything else through."""
    if feature in LOG_TRANSFORM_FEATURES:
        return math.log1p(max(value, 0))
    return value


def is_baseline_traffic(fv):
    """
    Select which feature vectors represent NORMAL traffic for the baseline.
    """
    return True


def compute_baseline(feature_vectors):
    baseline = {}
    for feature in ZSCORE_FEATURES:
        values = [transform_value(feature, fv[feature]) for fv in feature_vectors if feature in fv]
        if not values:
            continue
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std < MIN_STD_FLOOR:
            std = MIN_STD_FLOOR
        baseline[feature] = {"mean": mean, "std": std}
    return baseline


def zscore_detect(fv, baseline):

    max_z = 0.0
    trigger = None

    for feature, stats in baseline.items():
        if feature not in fv:
            continue
        val = transform_value(feature, fv[feature])
        z = abs((val - stats["mean"]) / stats["std"])
        if z > max_z:
            max_z = z
            trigger = feature

    is_anomaly = max_z > Z_THRESHOLD
    return is_anomaly, max_z, trigger



def rule_detect(fv):
    
    alerts = []

    # --- Port Scan Rule ---
    if (fv.get("unique_dst_ports", 0) > 40 and
        fv.get("avg_bytes_per_conn", 0) < 100 and
        fv.get("reject_ratio", 0) > 0.8):
        alerts.append({
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": (f"unique_dst_ports={fv['unique_dst_ports']}, "
                       f"avg_bytes={fv['avg_bytes_per_conn']:.1f}, "
                       f"reject={fv['reject_ratio']:.2f}")
        })

    # --- SSH Brute Force Rule ---
    if (fv.get("port_22_count", 0) > 0 and
        fv.get("total_connections", 0) > 100 and
        fv.get("avg_bytes_per_conn", 0) < 150):
        alerts.append({
            "type": "SSH_BRUTE_FORCE",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": (f"port_22_count={fv['port_22_count']}, "
                       f"connections={fv['total_connections']}")
        })

    # --- ICMP Flood Rule  ---
    if (fv.get("primary_protocol") == 1 and
        fv.get("total_packets", 0) > 500):
        alerts.append({
            "type": "ICMP_FLOOD",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": f"protocol=ICMP, packets={fv['total_packets']}"
        })

    return alerts



def run_detection():
    with open(FEATURES_FILE, "r") as f:
        all_vectors = json.load(f)

    baseline_vectors = [fv for fv in all_vectors if is_baseline_traffic(fv)]
    analyse_vectors  = all_vectors  

    print(f"Total vectors loaded: {len(all_vectors)}")
    print(f"Baseline vectors (normal): {len(baseline_vectors)}")
    print(f"Z-Score threshold: {Z_THRESHOLD} sigma\n")

    if len(baseline_vectors) < 5:
        print("WARNING: Your baseline has fewer than 5 vectors.")
        print("Edit is_baseline_traffic() to include more normal traffic.")
        return

    baseline = compute_baseline(baseline_vectors)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"Saved baseline profile to: {BASELINE_FILE}\n")

    alerts_log = []
    detection_count = {"PORT_SCAN": 0, "SSH_BRUTE_FORCE": 0, "ICMP_FLOOD": 0, "ZSCORE_ANOMALY": 0}

    print("=" * 70)
    print("DETECTION RESULTS")
    print("=" * 70)

    for fv in analyse_vectors:
        ts = datetime.utcfromtimestamp(fv["window_start"]).strftime('%Y-%m-%d %H:%M:%S')
        src_ip = fv["src_ip"]
        rule_alerts = rule_detect(fv)
        is_anomaly, max_z, trigger = zscore_detect(fv, baseline)

        if rule_alerts or is_anomaly:
            print(f"\n[{ts}] Source: {src_ip}")

            for alert in rule_alerts:
                detection_count[alert["type"]] += 1
                alert_record = {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "alert_type": alert["type"],
                    "severity": alert["severity"],
                    "confidence": alert["confidence"],
                    "triggering_method": "RULE",
                    "reason": alert["reason"],
                    "features": {k: fv.get(k) for k in ZSCORE_FEATURES}
                }
                alerts_log.append(alert_record)
                print(f"  [RULE] {alert['type']:15} | {alert['severity']} | {alert['reason']}")

            if is_anomaly:
                detection_count["ZSCORE_ANOMALY"] += 1
                alert_record = {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "alert_type": "STATISTICAL_ANOMALY",
                    "severity": "MEDIUM",
                    "confidence": round(min(max_z / 10.0, 1.0), 3),
                    "triggering_method": "ZSCORE",
                    "reason": f"max_z_score={max_z:.2f}, trigger={trigger}",
                    "features": {k: fv.get(k) for k in ZSCORE_FEATURES}
                }
                alerts_log.append(alert_record)
                print(f"  [Z-SC] ANOMALY         | MEDIUM | z={max_z:.2f} (trigger: {trigger})")
                print(f"         conn={fv['total_connections']}, ports={fv['unique_dst_ports']}, "
                      f"bytes={fv['avg_bytes_per_conn']:.1f}, reject={fv['reject_ratio']:.2f}")


    with open(ALERTS_FILE, "w") as f:
        for alert in alerts_log:
            f.write(json.dumps(alert) + "\n")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for k, v in detection_count.items():
        if v > 0:
            print(f"  {k:20}: {v}")
    print(f"\nAlerts written to: {ALERTS_FILE}")


if __name__ == "__main__":
    run_detection()