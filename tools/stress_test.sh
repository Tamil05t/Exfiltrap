#!/usr/bin/env bash
# ExFilTrap STRESS TEST v2 — random-domain storm + close watching.
#
# Unprivileged launch:  bash tools/stress_test.sh  (ONE sudo popup)
#
# Phase 1  RANDOM-DOMAIN STORM (3 min, 8 q/s): fresh DGA-style domains that
#          have never existed, interleaved with malicious-LOOKING names
#          (ransomware.com, c2server.com, ...) and everyday names.
# Phase 1b DIFFERENTIAL PROBE: plain everyday queries from the ATTACKER IP
#          (.2) — verifies capture works for that source BEFORE the attack.
# Phase 2  short 100 q/s burst (5 clients).
# Phase 3  fast-tunnel attack from .2 + IMMEDIATE per-source verification,
#          block check, canary. Evidence, teardown.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/.venv/bin/python"
LOGDIR=/tmp/exfiltrap-stress
EVID="$LOGDIR/evidence.txt"
RUN_USER="${SUDO_USER:-tamilarasu}"
BENIGN_IPS="10.99.0.3 10.99.0.10 10.99.0.11 10.99.0.12 10.99.0.13 10.99.0.14"

if [[ ${EUID} -ne 0 ]]; then
    ASKPASS="$REPO/tools/.stress_askpass.sh"
    printf '#!/bin/bash\nexec zenity --password --title="ExFilTrap STRESS v2 needs sudo (once)" 2>/dev/null\n' > "$ASKPASS"
    chmod 700 "$ASKPASS"
    export SUDO_ASKPASS="$ASKPASS"
    exec sudo -A -E bash "$0" "$@"
fi
trap 'rm -f "$REPO/tools/.stress_askpass.sh"' EXIT

mkdir -p "$LOGDIR"; rm -f "$LOGDIR"/*.log "$EVID" "$REPO/data/stress.db"*
exec > >(tee -a "$EVID") 2>&1
say() { echo; echo "### $1 ###"; }
db_count() {
    # Buffered writes commit on flush; /api/stats triggers one in-process,
    # so DB reads never see stale buffers.
    ip netns exec nsA curl -s --max-time 2 http://127.0.0.1:5050/api/stats >/dev/null 2>&1 || true
    "$PY" -c "import sqlite3,sys
print(sqlite3.connect('file:$REPO/data/stress.db?mode=ro', uri=True).execute(sys.argv[1]).fetchone()[0])" "$1" 2>/dev/null || echo "?"
}

say "0. setup"
iptables-save > "$LOGDIR/host_before.txt" 2>/dev/null || true
"$REPO/tools/netns_teardown.sh" >/dev/null 2>&1 || true
pkill -9 -f "exfiltrap.service" 2>/dev/null || true; sleep 1
"$REPO/tools/netns_setup.sh" >/dev/null
for i in 10 11 12 13 14; do
    ip netns exec nsB ip addr add "10.99.0.$i/24" dev veth-atk
done

say "1. service (iptables mitigation, benign IPs allowlisted, syslog alerts)"
ip netns exec nsA "$PY" -m exfiltrap.service --iface veth-gw \
    --db "$REPO/data/stress.db" --mitigation iptables --execute --alert syslog \
    --allowlist "$(echo $BENIGN_IPS | tr ' ' ',')" --block-ttl 600 \
    --flush-every 100 > "$LOGDIR/service.log" 2>&1 &
SVC_PID=$!
sleep 4
chown "$RUN_USER": "$REPO/data/stress.db"* 2>/dev/null || true
( while kill -0 "$SVC_PID" 2>/dev/null; do
      ps -p "$SVC_PID" -o %cpu,rss --no-headers >> "$LOGDIR/resources.log"
      sleep 5; done ) &

say "2. PHASE 1 — RANDOM-DOMAIN STORM (fresh DGA + malicious + everyday, 8 q/s, 180s)"
ip netns exec nsB "$PY" "$REPO/tools/stress_traffic.py" \
    --target 10.99.0.1 --profile random --qps 8 --duration 180 \
    --source-ip 10.99.0.3 --seed 424242 || true
sleep 3
echo "storm processed: $(db_count 'SELECT COUNT(*) FROM queries') queries, $(db_count "SELECT COUNT(*) FROM queries WHERE risk_level IN ('HIGH','CONFIRMED')") flagged"

say "2b. PHASE 1b — DIFFERENTIAL PROBE from the ATTACKER IP (.2, plain queries)"
ip netns exec nsB "$PY" "$REPO/tools/stress_traffic.py" \
    --target 10.99.0.1 --profile random --qps 2 --duration 15 \
    --source-ip 10.99.0.2 --seed 99 || true
sleep 3
P2=$(db_count "SELECT COUNT(*) FROM queries WHERE src_ip='10.99.0.2'")
echo "DIFFERENTIAL PROBE: sent ~30 plain queries from .2 -> captured rows from .2: $P2"
if [ "$P2" = "0" ]; then
    echo "ANOMALY CONFIRMED AT SOURCE-IP LEVEL: capture drops .2 even for plain queries"
elif [ "$P2" -lt 20 ] 2>/dev/null; then
    echo "PARTIAL capture from .2 ($P2/30) — lossy, not absent"
else
    echo "capture healthy for .2 — run-3 anomaly was qname/attack-specific"
fi

say "3. PHASE 2 — 100 q/s burst, 30 s, 5 clients"
senders=()
for ip in 10 11 12 13 14; do
    ip netns exec nsB "$PY" "$REPO/tools/stress_traffic.py" \
        --target 10.99.0.1 --profile random --qps 20 --duration 30 \
        --source-ip "10.99.0.$ip" >> "$LOGDIR/burst.log" 2>&1 &
    senders+=($!)
done
wait "${senders[@]}"
sleep 2
echo "after burst: $(db_count 'SELECT COUNT(*) FROM queries') total, $(db_count "SELECT COUNT(*) FROM queries WHERE risk_level IN ('HIGH','CONFIRMED')") flagged"

say "4. PHASE 3 — fast tunnel attack from .2 + IMMEDIATE verification"
B4=$(db_count "SELECT COUNT(*) FROM queries WHERE src_ip='10.99.0.2'")
ip netns exec nsB "$PY" "$REPO/tools/attacker_client.py" \
    --target 10.99.0.1 --mode fast --duration 10 || true
sleep 4
A4=$(db_count "SELECT COUNT(*) FROM queries WHERE src_ip='10.99.0.2'")
F4=$(db_count "SELECT COUNT(*) FROM queries WHERE src_ip='10.99.0.2' AND risk_level IN ('HIGH','CONFIRMED')")
echo "ATTACK VERIFICATION: .2 rows $B4 -> $A4 (captured $((A4-B4)) of ~200 sent), flagged: $F4"
echo "mitigation refusals logged: $(grep -c 'REFUSED\|mitigation failed' "$LOGDIR/service.log" 2>/dev/null || true)"

say "5. EVIDENCE — block state + canary"
ip netns exec nsA iptables -S INPUT || true
C0=$(ip netns exec nsA iptables -L INPUT -v -x 2>/dev/null | awk '/DROP/{s+=$1} END{print s+0}')
ip netns exec nsB "$PY" - <<'PYEOF' 2>/dev/null || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.99.0.2", 0))
for _ in range(5):
    s.sendto(b"\x99\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", ("10.99.0.1", 53))
PYEOF
sleep 2
C1=$(ip netns exec nsA iptables -L INPUT -v -x 2>/dev/null | awk '/DROP/{s+=$1} END{print s+0}')
echo "DROP-rule counter: $C0 -> $C1 (delta $((C1-C0)))"
iptables-save > "$LOGDIR/host_after.txt" 2>/dev/null || true
diff "$LOGDIR/host_before.txt" "$LOGDIR/host_after.txt" \
    && echo "OK: host firewall identical" || true
say "5a. final status"
ip netns exec nsA curl -s --max-time 3 http://127.0.0.1:5050/api/status || true; echo
say "5b. resources"
awk '{c+=$1; if($1>mc)mc=$1; r+=$2; if($2>mr)mr=$2; n++}
     END {if(n>0) printf "service CPU: avg %.1f%% max %.1f%% | RSS: avg %d MiB max %d MiB\n",
          c/n, mc, r/n/1024, mr/1024}' "$LOGDIR/resources.log" || true
say "5c. journal sample"
timeout 5 journalctl --no-pager -t exfiltrap -n 3 2>/dev/null || echo "(journal unavailable)"

say "6. teardown"
kill "$SVC_PID" 2>/dev/null || true; sleep 6  # let the graceful finalizer flush
pkill -9 -f "exfiltrap.service --iface" 2>/dev/null || true
chown "$RUN_USER": "$REPO/data/stress.db"* 2>/dev/null || true
"$REPO/tools/netns_teardown.sh"
echo; echo "=== stress v2 finished — $(date) ==="
