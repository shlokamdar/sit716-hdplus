#!/bin/bash

set -u

TARGET_IP="${1:-}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: sudo ./run_port_scan.sh <target_private_ip>"
    exit 1
fi

MY_IP=$(hostname -I | awk '{print $1}')

echo "=============================================================="
echo "IDS - PORT SCAN DEMO"
echo "Attacker: $MY_IP"
echo "Target:   $TARGET_IP"
echo "=============================================================="

ATTACK_START=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

nmap -Pn \
     -sS \
     -p 1-21,23-1000 \
     -T5 \
     --max-retries 1 \
     --host-timeout 45s \
     "$TARGET_IP" || true

sleep 2

nmap -Pn \
     -sS \
     -p 1-21,23-1000 \
     -T5 \
     --max-retries 1 \
     --host-timeout 45s \
     "$TARGET_IP" || true

ATTACK_END=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

echo "Attack completed successfully."
echo "=============================================================="
echo "ATTACK_START=$ATTACK_START"
echo "ATTACK_END=$ATTACK_END"
echo "=============================================================="