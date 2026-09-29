# Cloud Intrusion Detection and Automated Response Using AWS VPC Flow Logs

**SIT716 — Computer Networks and Security | 6.2HD Plus — Project Delivery**
Shloka Hitesh Kamdar (226463713) · Master of Cyber Security, Deakin University

A cloud-native intrusion detection system built entirely on AWS, using VPC Flow Logs as its only telemetry source. It combines a deterministic rule engine with a statistical (Z-score) anomaly detector to identify port scanning, SSH brute-force attempts and ICMP floods. Detected attackers are contained automatically with a time-bound **Network ACL DENY** entry on the target's subnet, which is removed automatically after 15 minutes.

- **Original report:** [`SIT716_Project_Report.pdf.pdf`](./SIT716_Project_Report.pdf.pdf) (submitted 18 September 2026)
- **Supplementary evidence report:** submitted separately (29 September 2026) 
- **Presentation recording:** [DeakinAir](https://deakin.au.panopto.com/Panopto/Pages/Viewer.aspx?id=5ba8d09f-de41-4ab1-a83e-b4c9009c1dc0)
- **Slides:** [`SIT716_Presentation_Slides.pptx`](./SIT716_Presentation_Slides.pptx)

---

## Post-submission update (29 September 2026)

The version submitted on 18 September responded to detections by adding a Security Group rule. Security Groups only support *allow* rules, so that rule permitted the attacker's traffic instead of blocking it (see the original report, Section 5.2). The response recorded a block but did not contain the attacker.

After submission, enforcement was moved to a Network ACL, which supports explicit DENY rules.
The changes are:

| Area | Change |
|---|---|
| Networking | The target moved to a dedicated subnet, `IDS-Target-Subnet` (`10.0.2.0/24`), with its own NACL, `IDS-Target-NACL`. A NACL only filters traffic that crosses a subnet boundary, so the target could not share a subnet with the attackers. |
| `add_block` | Creates an inbound NACL DENY entry for the attacker's `/32` before anything else, then records the block. |
| `remove_expired_blocks` | Deletes the NACL entry and its state record once expired. It now runs every **1 minute** instead of every 15 minutes. |
| IAM | The Lambda role gained `ec2:CreateNetworkAclEntry`, `ec2:DeleteNetworkAclEntry`, `ec2:DescribeNetworkAcls` and `ec2:ReplaceNetworkAclEntry`. |
| Target Security Group | Now allows only TCP 22, 80, 443 and ICMP from the attacker subnet. Previously it allowed all TCP from `10.0.1.0/24`. |

All changes relative to the submitted version:
[compare `d9a13f1`…`main`](https://github.com/shlokamdar/sit716-hdplus/compare/d9a13f1...main).
Commit `d9a13f1` is the last commit of the 18 September submission.

---

## Architecture

Four EC2 instances in one custom VPC (`10.0.0.0/16`), split across two subnets. Addresses
shown are from the evaluated deployment; AWS assigns them at launch.

| Instance | Subnet | Address | Role |
|---|---|---|---|
| Target-Server | `IDS-Target-Subnet` `10.0.2.0/24` | `10.0.2.79` | Protected asset |
| Attacker-Server | `IDS-Public-Subnet` `10.0.1.0/24` | `10.0.1.194` | Port scan source |
| Attacker-Server-2 | `IDS-Public-Subnet` `10.0.1.0/24` | `10.0.1.70` | SSH brute-force source |
| Detection-Server | `IDS-Public-Subnet` `10.0.1.0/24` | `10.0.1.155` | Detection and response pipeline |

Both subnets use the same public route table. VPC Flow Logs are enabled at VPC level with a
60-second aggregation interval and delivered to the CloudWatch Logs group `/aws/vpc/ids-flow-logs`.

```
            VPC Flow Logs (60 s aggregation) → CloudWatch Logs
                                 │
                       polled every 60 s (boto3)
                                 │
                       ┌─────────▼─────────┐
                       │  Detection-Server │  rule-based + Z-score detection
                       └─────────┬─────────┘
                  HIGH severity  │               every 1 min (EventBridge)
                       ┌─────────▼─────────┐     ┌───────────────────────┐
                       │     add_block     │     │ remove_expired_blocks │
                       └──┬─────────────┬──┘     └──┬─────────────────┬──┘
           1. DENY entry  │             │ 2. state  │ delete entry    │ revoke record
                ┌─────────▼────────┐ ┌──▼───────────▼───┐             │
                │ IDS-Target-NACL  │ │ Target Security  │◄────────────┘
                │ (enforcement)    │ │ Group (state     │
                │ rules 100–499    │ │ record only)     │
                └─────────┬────────┘ └──────────────────┘
                          │ ◄───────────────────────────────────── (NACL delete)
                  IDS-Target-Subnet → Target-Server
```

---

## How containment works

**Why a NACL.** A NACL supports explicit DENY rules and evaluates rules in ascending order.
Each attacker-specific DENY uses a rule number between 100 and 499, so it is matched before the baseline `1000 ALLOW 0.0.0.0/0`, and the attacker's packets are dropped before they reach the instance. Only inbound entries are managed; the baseline outbound rule is unchanged.

**Blocking (`add_block`).** For each HIGH-severity detection the Lambda function:

1. Skips whitelisted addresses (the management IP and the AWS metadata service).
2. Reuses an existing managed DENY entry for the same `/32`, or allocates the smallest free
   rule number in the range 100–499.
3. Creates the inbound DENY entry (all protocols) on `IDS-Target-NACL`.
4. Writes a Security Group rule whose description holds the block's state:
   `auto-blocked;nacl_rule=<n>;blocked_at=<ts>;expiry=<ts>;reason=<rule>`.
5. Rolls back the NACL entry if the Security Group write fails.

The NACL entry is created first, so a block is never recorded without being enforced.

**Why a Security Group rule is still written.** NACL entries have no description field. The Security Group rule description is used as the state store, so there is no separate database to fall out of sync. Its inbound *allow* has no enforcement effect while the NACL DENY is present, because the NACL drops the traffic first.

**Expiry (`remove_expired_blocks`).** Every minute, the function reads the tagged Security Group rules, and for each expired one deletes the NACL entry named in `nacl_rule` and then revokes the Security Group rule.

---

## Repository structure

```
.
├── terraform/
│   ├── main.tf               # VPC, both subnets, target NACL + association, security groups,
│   │                         # IAM roles, flow logs, EC2 instances
│   ├── lambda.tf             # add_block / remove_expired_blocks deployment, env vars
│   │                         # (TARGET_SG_ID, TARGET_NACL_ID), EventBridge 1-minute schedule
│   ├── variables.tf          # Input variables (region, key name, CIDRs)
│   ├── terraform.tfvars      # Variable values — contains a personal IP, do not reuse
│   └── outputs.tf            # Instance IPs and SSH commands (target_nacl_id is output from main.tf)
│
├── detection-engine/         # Runs on the Detection-Server
│   ├── config.py             # AWS region, CloudWatch log group, flow-log field order
│   ├── fetcher.py            # Pulls raw flow log events from CloudWatch
│   ├── parser.py             # Parses raw records into structured fields
│   ├── aggregator.py         # 60 s per-source windows, 9 behavioural features
│   ├── detection_engine.py   # Rule-based detector + Z-score detector
│   ├── state_manager.py      # Per-IP / per-severity 5-minute alert deduplication
│   ├── responder.py          # Invokes the add_block Lambda
│   ├── run_cycle.py          # One fetch → detect → respond cycle (cron entry point)
│   ├── calculate_metrics.py  # Scores decisions against ground_truth.json
│   ├── dashboard.py          # CLI dashboard
│   ├── web_dashboard.py      # Flask web dashboard
│   ├── blocklist_utils.py    # State-record build/parse helpers
│   └── timezone_utils.py     # UTC → IST display conversion
│
├── lambda functions/         # Packaged and deployed by terraform/lambda.tf
│   ├── add_block.py          # Whitelist check → NACL DENY → state record (with rollback)
│   ├── remove_expired_blocks.py  # Deletes expired NACL entries and state records
│   └── blocklist_utils.py    # State-record format incl. nacl_rule; managed rule range 100–499
│
├── attack stimulation/
│   ├── run_port-scan.sh      # nmap SYN scan — Attacker-Server
│   ├── run_ssh.sh            # High-volume TCP/22 connection burst — Attacker-Server-2
│   ├── mixed_test.sh         # Normal → attack → normal script used during development
│   └── ground_truth.json     # Attack windows for calculate_metrics.py
│
├── SIT716_Project_Report.pdf.pdf
└── SIT716_Presentation_Slides.pptx
```

---

## How detection works

Detection is unchanged by the post-submission update.

**Baseline.** A 45–60 minute capture of normal traffic, aggregated into 60-second
per-source-IP windows across 9 features: `total_connections`, `unique_dst_ports`,
`avg_bytes_per_conn`, `avg_packets_per_conn`, `reject_ratio`, `total_packets`, `total_bytes`,
`connections_per_second`, `avg_duration_seconds`.

**Statistical layer.** A Z-score per feature against the baseline mean and standard deviation,
with log1p applied to the four heavy-tailed volume features. A maximum Z-score above 4.0σ
produces a MEDIUM-severity anomaly.

**Rule-based layer** (HIGH severity):

| Rule | Condition |
|---|---|
| `PORT_SCAN` | `unique_dst_ports > 40 AND avg_bytes_per_conn < 100 AND reject_ratio > 0.8` |
| `SSH_BRUTE_FORCE` | `port_22_count > 0 AND total_connections > 100 AND avg_bytes_per_conn < 150` |
| `ICMP_FLOOD` | `primary_protocol == ICMP AND total_packets > 500` |

Only HIGH-severity rule matches trigger containment. MEDIUM anomalies are logged and shown on
the dashboards but never block anything, because the statistical layer produces many false
positives (see Results).

---

## Results

Detection rate must be read together with false-positive rate and precision. In both runs,
most flagged windows were not attacks.

| Metric | Original run, 18 Sep | Supplementary Run C, 29 Sep |
|---|---|---|
| Target | `10.0.1.65` (shared subnet) | `10.0.2.79` (dedicated subnet) |
| Windows analysed | 561 | 639 |
| TP / FP / TN / FN | 15 / 92 / 454 / 0 | 10 / 58 / 571 / 0 |
| Detection rate | 1.000 | 1.000 |
| False-positive rate | 0.168 | 0.092 |
| Precision | 0.140 | 0.147 |
| Detection interval, 10.0.1.194 | 37 s | 43 s |
| Detection interval, 10.0.1.70 | 20 s | 52 s |
| Containment | None (Security Group rule allowed traffic) | NACL DENY, verified in separate enforcement runs |

The detection interval is the time from the recorded attack start to the first window in which
the attacker was detected, as calculated by `calculate_metrics.py`. It is not the time taken to
block the attacker. The two runs differ in target, subnet, Security Group rules and traffic
conditions, so the difference in false-positive rate is not attributed to any change.

In the supplementary enforcement demonstration, attacker traffic was blocked about 63 s
(port scan) and 91 s (SSH brute force) after each attack was launched. Both attackers lost
ping and TCP/22 connectivity while the DENY entries were active, a non-blocked host kept
connectivity, and both attackers regained connectivity after the entries expired. CloudTrail
recorded the `CreateNetworkAclEntry` and `DeleteNetworkAclEntry` calls. The full evidence is
in the supplementary evidence report.


---

## Known limitations

- **Rule capacity.** A NACL holds a limited number of rules per direction (20 by default),
  which caps how many attackers can be blocked at once, well below the 100–499 managed range.
- **False positives.** Precision was about 0.15 in both evaluation runs; the statistical layer
  is not suitable for automated action.
- **Baseline.** The Z-score baseline was collected against the original target (`10.0.1.65`)
  and has not been re-collected for `10.0.2.79`.
- **Flow Log delivery lag.** Delivery to CloudWatch has varied from under a minute to 15–20
  minutes, and dominates the time to containment.
- **Out-of-band detection.** Detection uses flow logs after the traffic has occurred. This is
  an IDS with automated response, not an inline IPS, and it has no visibility of payloads.
- **Scope.** Single VPC and account. `ICMP_FLOOD` containment has not been tested.
