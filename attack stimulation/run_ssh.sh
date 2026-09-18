#!/bin/bash

set -u

TARGET_IP="${1:-}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: ./run_ssh.sh <target_private_ip>"
    exit 1
fi

MY_IP=$(hostname -I | awk '{print $1}')

echo "=============================================================="
echo "IDS - SSH BRUTE FORCE DEMO"
echo "Attacker: $MY_IP"
echo "Target:   $TARGET_IP"
echo "=============================================================="

ATTACK_START=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

echo "Generating attack traffic..."

ATTEMPTS=0

# Generate SSH connection attempts for 60 seconds.
END_TIME=$((SECONDS + 60))

while [ $SECONDS -lt $END_TIME ]; do

    timeout 0.30 bash -c \
        "(echo > /dev/tcp/$TARGET_IP/22) 2>/dev/null" || true

    ATTEMPTS=$((ATTEMPTS + 1))

    if (( ATTEMPTS % 100 == 0 )); then
        echo "Generating attack traffic..."
    fi

done

ATTACK_END=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

echo "Attack completed successfully."
echo "=============================================================="
echo "ATTACK_START=$ATTACK_START"
echo "ATTACK_END=$ATTACK_END"
echo "=============================================================="