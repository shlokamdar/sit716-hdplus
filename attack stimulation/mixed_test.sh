set -e

TARGET_IP="$1"
if [ -z "$TARGET_IP" ]; then
    echo "Usage: ./mixed_test.sh <target_private_ip>"
    exit 1
fi

MY_IP=$(hostname -I | awk '{print $1}')

log_ts() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%S+00:00)] $1"
}

iso_now() {
    date -u +%Y-%m-%dT%H:%M:%S+00:00
}

echo "======================================================================"
echo "Mixed Traffic Test — Attacker: $MY_IP — Target: $TARGET_IP"
echo "======================================================================"
log_ts "TEST_START"
TEST_START=$(iso_now)

log_ts "Starting 10 minutes of NORMAL traffic..."
NORMAL_END=$((SECONDS + 600))
while [ $SECONDS -lt $NORMAL_END ]; do
    ping -c 1 -W 1 "$TARGET_IP" > /dev/null 2>&1 || true
    curl -s -m 2 "http://$TARGET_IP" > /dev/null 2>&1 || true
    sleep 5
done
log_ts "Finished normal traffic phase A."
log_ts "ATTACK_START"
ATTACK_START=$(iso_now)

log_ts "Running nmap port scan (1-1000)..."
nmap -Pn -p 1-1000 "$TARGET_IP" || true

log_ts "Running SSH brute-force simulation..."

if command -v hydra >/dev/null 2>&1; then
    if [ -f /usr/share/wordlists/rockyou.txt ]; then
        WORDLIST=/usr/share/wordlists/rockyou.txt
    else
        WORDLIST=/tmp/small_wordlist.txt
        printf "password\n123456\nadmin\nletmein\nqwerty\n" > "$WORDLIST"
    fi
    timeout 15 hydra -l admin -P "$WORDLIST" -t 4 "ssh://$TARGET_IP" || true
else
    log_ts "hydra not installed — skipping to the connection burst below"
fi

ATTEMPTS=0
BURST_END=$((SECONDS + 60))
while [ $SECONDS -lt $BURST_END ]; do
    timeout 0.3 bash -c "(echo > /dev/tcp/$TARGET_IP/22) 2>/dev/null" || true
    ATTEMPTS=$((ATTEMPTS + 1))
done
log_ts "Connection burst complete: $ATTEMPTS attempts made in ~60 seconds."
if [ $ATTEMPTS -lt 100 ]; then
    log_ts "WARNING: only $ATTEMPTS attempts — below the 100 needed to trip SSH_BRUTE_FORCE. This shouldn't happen with the 0.3s timeout wrapper; check network connectivity to the Target if it does."
fi

log_ts "ATTACK_END"
ATTACK_END=$(iso_now)

log_ts "Starting 5 minutes of NORMAL traffic..."
NORMAL2_END=$((SECONDS + 300))
while [ $SECONDS -lt $NORMAL2_END ]; do
    ping -c 1 -W 1 "$TARGET_IP" > /dev/null 2>&1 || true
    curl -s -m 2 "http://$TARGET_IP" > /dev/null 2>&1 || true
    sleep 5
done
log_ts "Finished normal traffic phase C."

log_ts "TEST_END"
TEST_END=$(iso_now)

echo "======================================================================"
echo "Test complete."
echo ""
echo "1) test_start / test_end"
echo "   \"test_start\": \"$TEST_START\","
echo "   \"test_end\":   \"$TEST_END\""
echo ""
echo "======================================================================"