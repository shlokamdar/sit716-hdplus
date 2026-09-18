# Cloud Intrusion Detection and Automated Response Using AWS VPC Flow Logs

**SIT716 — Computer Networks and Security | 6.2HD Plus — Project Delivery**
Shloka Hitesh Kamdar (226463713) · Master of Cyber Security, Deakin University

A cloud-native intrusion detection system built entirely on AWS, using VPC Flow Logs as its
only telemetry source. It combines a deterministic rule engine with a statistical (Z-score)
anomaly detector to identify port scanning, SSH brute-force attempts, and ICMP floods, and
automatically contains detected threats through a Lambda-triggered, time-bound Security Group
rule that expires on its own after 15 minutes.

📄 **Full report:** submitted separately as `SIT716_Project_Report.pdf`
🎥 **Presentation recording:** [DeakinAir](https://deakin.au.panopto.com/Panopto/Pages/Viewer.aspx?id=5ba8d09f-de41-4ab1-a83e-b4c9009c1dc0)
📊 **Slides:** [`SIT716_Presentation_Slides.pptx`](./SIT716_Presentation_Slides.pptx)

---

## Architecture

Four EC2 instances inside a single custom VPC (`10.0.0.0/16`, public subnet):

- **Target-Server** — the protected asset
- **Attacker-Server** / **Attacker-Server-2** — independent attacker instances used for
  distributed, multi-source attack simulation
- **Detection-Server** — runs the full detection and response pipeline on a 60-second cron cycle

VPC Flow Logs stream to CloudWatch Logs. The Detection-Server pulls new records every 60
seconds via `boto3`, aggregates them into per-source-IP behavioural windows, and runs them
through two detection layers in parallel. A HIGH-severity rule match asynchronously invokes
the `add_block` Lambda, which tags and adds a temporary Security Group rule; a second Lambda,
`remove_expired_blocks`, sweeps the Security Group every 15 minutes via EventBridge and removes
anything past its expiry. Two dashboards (CLI and web) read live from the same alert log and
query the Security Group directly, so there's no separate state to fall out of sync.

```
                 VPC Flow Logs → CloudWatch Logs
                          │
                 polled every 60s (boto3)
                          │
                 ┌────────▼────────┐
                 │ Detection-Server │──rule + Z-score detection
                 └────────┬────────┘
              HIGH severity│  │ every 15 min (EventBridge)
                 ┌─────────▼┐┌▼─────────────────┐
                 │ add_block││ remove_expired_blocks│
                 └─────────┬┘└──────────────────┘
                 ┌─────────▼─────────┐
                 │ Target Security Group │ (tagged rule, 15-min auto-expiry)
                 └────────────────────┘
```

---

## Repository structure

```
.
├── terraform/                  # Infrastructure as code
│   ├── main.tf                 # VPC, subnets, EC2 instances, security groups, IAM roles
│   ├── lambda.tf                # add_block / remove_expired_blocks Lambda deployments + EventBridge
│   ├── variables.tf            # Input variables (region, key name, CIDRs)
│   ├── terraform.tfvars        # Variable values (⚠ contains a personal IP — sanitise before pushing)
│   └── outputs.tf              # Public/private IPs and SSH command outputs
│
├── detection-engine/            # Runs on the Detection-Server
│   ├── config.py                # AWS region, CloudWatch log group, flow-log field order
│   ├── fetcher.py               # Pulls raw flow log events from CloudWatch
│   ├── parser.py                # Parses raw records into structured fields
│   ├── aggregator.py            # Groups records into 60s windows, computes the 9 behavioural features
│   ├── detection_engine.py      # Rule-based detector + Z-score statistical detector
│   ├── state_manager.py         # Per-IP/per-severity 5-minute alert deduplication
│   ├── responder.py             # Invokes the add_block Lambda
│   ├── run_cycle.py             # Orchestrates one full fetch → detect → respond cycle (cron entrypoint)
│   ├── calculate_metrics.py     # Scores the decision log against ground_truth.json (TP/FP/TN/FN, rates)
│   ├── dashboard.py              # CLI dashboard
│   ├── web_dashboard.py         # Flask web dashboard
│   ├── blocklist_utils.py       # Shared Security Group description tag build/parse helpers
│   └── timezone_utils.py        # UTC → IST display conversion
│
├── lambda-functions/            # Deployed as AWS Lambda (packaged by terraform/lambda.tf)
│   ├── add_block.py             # Whitelist check + AuthorizeSecurityGroupIngress
│   ├── remove_expired_blocks.py # Sweeps and revokes expired Security Group rules
│   └── blocklist_utils.py       # Self-contained copy (Lambda packages can't import from outside the zip)
│
├── attack-simulation/            # Attack + baseline traffic generation
│   ├── run_port-scan.sh          # nmap SYN scan (ports 1-21, 23-1000) — used by Attacker-Server
│   ├── run_ssh.sh                # High-volume port-22 connection burst — used by Attacker-Server-2
│   ├── mixed_test.sh              # Combined normal→attack→normal script used during development
│   └── ground_truth.json         # Recorded attack windows for the formal multi-attacker test
│
└── SIT716_Presentation_Slides.pptx
```


## How detection works

**Baseline** — a 45–60 minute capture of normal traffic before any attack simulation, aggregated
into 60-second per-source-IP windows across 9 features (`total_connections`, `unique_dst_ports`,
`avg_bytes_per_conn`, `avg_packets_per_conn`, `reject_ratio`, `total_packets`, `total_bytes`,
`connections_per_second`, `avg_duration_seconds`).

**Statistical layer** — Z-score per feature against the baseline mean/std (log1p-transformed for
the four heavy-tailed volume features). Max Z-score > 4.0σ → MEDIUM-severity anomaly.

**Rule-based layer** (HIGH severity, confidence 1.0):
| Rule | Condition |
|---|---|
| `PORT_SCAN` | `unique_dst_ports > 40 AND avg_bytes_per_conn < 100 AND reject_ratio > 0.8` |
| `SSH_BRUTE_FORCE` | `port_22_count > 0 AND total_connections > 100 AND avg_bytes_per_conn < 150` |
| `ICMP_FLOOD` | `primary_protocol == ICMP AND total_packets > 500` |

Only HIGH-severity rule matches trigger an automatic block; MEDIUM anomalies are logged and
shown on the dashboards but never trigger a response, to keep automated action limited to
deterministic, high-confidence detections.

---

## Results — formal multi-attacker test

Two attacker instances launched a port scan and an SSH brute-force burst concurrently
(`2026-09-18T07:10:09Z` → `07:19:09Z`):

| Metric | Value |
|---|---|
| True Positives | 15 |
| False Positives | 92 |
| True Negatives | 454 |
| False Negatives | 0 |
| Detection Rate | 1.000 |
| False Positive Rate | 0.168 |
| Response Time — 10.0.1.70 (SSH) | 20 seconds |
| Response Time — 10.0.1.194 (Port Scan) | 37 seconds |

Full methodology, the rule-based vs. Z-score comparison, protocol-level Wireshark evidence, and
documented limitations are in the report.

---

## Deploying

```bash
cd terraform/
terraform init
terraform apply \
  -var="my_public_ip=<your-ip>/32" \
  -var="target_sg_cidr=<your-ip>/32" \
  -var="attacker_sg_cidr=<your-ip>/32" \
  -var="key_name=<your-ec2-key-pair-name>"
```

On the Detection-Server, install dependencies and run once against a clean baseline capture,
then schedule `run_cycle.py` every 60 seconds via cron. On each Attacker instance, run
`run_port-scan.sh <target_private_ip>` or `run_ssh.sh <target_private_ip>` to generate attack
traffic; each prints an `ATTACK_START` / `ATTACK_END` timestamp pair to feed into
`ground_truth.json` for `calculate_metrics.py`.

---

## Known limitations

- Single VPC / single AWS account scope — no cross-account or cross-region correlation.
- Security Groups only support allow rules, not true deny — `add_block` adds a scoped allow rule
  rather than a network-level drop (verified empirically; see report Section 5.2).
- VPC Flow Log delivery to CloudWatch can lag by up to 15–20 minutes, which dominates end-to-end
  response time more than detection processing itself.
- Detection is out-of-band (log-based), not inline packet inspection — an IDS with automated
  response, not a true IPS.

Full discussion in the report, Section 5.
