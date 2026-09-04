#!/usr/bin/env bash
# ExFilTrap LIVE deployment & test driver.
#
# Usage (unprivileged):   bash tools/deploy_live.sh
#   -> a GUI password popup appears ONCE (zenity); enter your sudo password.
#   -> the driver then runs as root for the full session: sets up the
#      nsA/nsB namespace lab, starts the detection service inside nsA with
#      REAL iptables mitigation, launches benign background traffic and a
#      slow-drip attack from nsB, fires a fast tunneling burst, collects
#      evidence, and tears everything down cleanly.
#
# Timeline (seconds from service start):
#    t=0     service starts in nsA (capture veth-gw, iptables mitigation on)
#    t=5     benign background from nsB (~1 qps, from the real top-50k corpus)
#    t=50    slow-drip tunnel from nsB (real 65s interval, encrypted hex)
#    t=~700  expected: stateful detector flags the drip -> iptables block
#    t=870   fast tunneling burst (45s) -> CONFIRMED + payload decode
#    t=~990  evidence collection, teardown
#
# While it runs, watch live:  http://127.0.0.1:5000  (host dashboard) or
# read data/live.db. Evidence: /tmp/exfiltrap_evidence.txt and
# eval/results/live_deployment_report.md (written by the supervisor).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/.venv/bin/python"
LOGDIR=/tmp/exfiltrap-live
EVID=/tmp/exfiltrap_evidence.txt
RUN_USER="${SUDO_USER:-tamilarasu}"

# ---------------------------------------------------------------- sudo gate
# ONE sudo invocation for the whole session. (A pre-auth `sudo -v` followed
# by a second sudo does not work here: with no controlling TTY the cached
# credential is not shared between the two calls, so the second one would
# prompt again — into a deleted askpass file.)
if [[ ${EUID} -ne 0 ]]; then
    ASKPASS="$REPO/tools/.live_askpass.sh"
    cat > "$ASKPASS" <<'EOF'
#!/bin/bash
if command -v zenity >/dev/null 2>&1 && [[ -n ${DISPLAY:-} ]]; then
    exec zenity --password --title="ExFilTrap live deployment needs sudo (once)" 2>/dev/null
elif command -v kdialog >/dev/null 2>&1; then
    exec kdialog --password "ExFilTrap live deployment needs sudo (once)" 2>/dev/null
fi
exit 1
EOF
    chmod 700 "$ASKPASS"
    export SUDO_ASKPASS="$ASKPASS"
    exec sudo -A -E bash "$0" "$@"
fi
trap 'rm -f "$REPO/tools/.live_askpass.sh"' EXIT

# ---------------------------------------------------------------- root driver
mkdir -p "$LOGDIR"; rm -f "$LOGDIR"/*.log "$EVID"
exec > >(tee -a "$EVID") 2>&1
echo "=== ExFilTrap live deployment — $(date) ==="
echo "driver running as: $(id -un)"

say() { echo; echo "### $1 ###"; }

say "0. cleanup of any previous lab + host firewall baseline"
iptables-save > "$LOGDIR/host_iptables_before.txt" 2>/dev/null || true
"$REPO/tools/netns_teardown.sh" || true

say "1. namespace lab (nsA=10.99.0.1 gateway, nsB=10.99.0.2 attacker)"
"$REPO/tools/netns_setup.sh"

say "2. detection service inside nsA (capture + REAL iptables mitigation + syslog alerting)"
rm -f "$REPO/data/live.db" "$REPO/data/live.db-wal" "$REPO/data/live.db-shm"
ip netns exec nsA "$PY" -m exfiltrap.service --iface veth-gw \
    --db "$REPO/data/live.db" --mitigation iptables --execute --alert syslog \
    --flush-every 50 --api-port 5050 > "$LOGDIR/service.log" 2>&1 &
SVC_PID=$!
sleep 4
chown "$RUN_USER": "$REPO/data/live.db" \
    "$REPO/data/live.db-wal" "$REPO/data/live.db-shm" 2>/dev/null || true
echo "service pid $SVC_PID; capture check:"
ip netns exec nsA curl -s --max-time 3 http://127.0.0.1:5050/api/status || true

say "3. benign background traffic from nsB, source IP 10.99.0.3 (multi-IP lab: stateful per-session detection now sees the drip as its own session)"
ip netns exec nsB "$PY" "$REPO/tools/benign_traffic_gen.py" \
    --target 10.99.0.1 --source-ip 10.99.0.3 --duration 1700 \
    > "$LOGDIR/benign.log" 2>&1 &
BEN_PID=$!
sleep 5

say "4. slow-drip tunnel from nsB (encrypted hex, real 65s interval)"
ip netns exec nsB "$PY" "$REPO/tools/attacker_client.py" \
    --target 10.99.0.1 --mode slow-drip --duration 1400 \
    > "$LOGDIR/slowdrip.log" 2>&1 &
DRIP_PID=$!
echo "waiting for the stateful detector to accumulate evidence on the drip..."

say "5. host dashboard for live watching: http://127.0.0.1:5000"
runuser -u "$RUN_USER" -- "$PY" -m exfiltrap.dashboard \
    --db "$REPO/data/live.db" --port 5000 > "$LOGDIR/hostui.log" 2>&1 &
UI_PID=$!

# t=0 for the phases below is roughly service start + 10s.
sleep 810   # -> ~t=870: drip has sent ~13 queries; flag expected since ~#10

say "6. fast tunneling burst from nsB (45s)"
ip netns exec nsB "$PY" "$REPO/tools/attacker_client.py" \
    --target 10.99.0.1 --mode fast --duration 45 || true
sleep 75

say "7. EVIDENCE — service status via nsA API"
ip netns exec nsA curl -s --max-time 3 http://127.0.0.1:5050/api/status || true
echo
say "7a. EVIDENCE — iptables rules INSIDE nsA (the block must be here)"
ip netns exec nsA iptables -S INPUT || true
say "7b. EVIDENCE — host firewall untouched (diff vs baseline = empty)"
iptables-save > "$LOGDIR/host_iptables_after.txt" 2>/dev/null || true
if diff "$LOGDIR/host_iptables_before.txt" "$LOGDIR/host_iptables_after.txt"; then
    echo "OK: host firewall ruleset identical to pre-deployment baseline"
else
    echo "WARNING: host firewall changed (should not happen)"
fi
say "7c. EVIDENCE — detector logs (CONFIRMED lines)"
grep -c "CONFIRMED" "$LOGDIR/service.log" || true
grep -m 3 "CONFIRMED exfil" "$LOGDIR/service.log" || true

say "7d. EVIDENCE — post-block canary: do packets actually hit the DROP rule?"
drop_count() { ip netns exec nsA iptables -L INPUT -v -x 2>/dev/null \
    | awk '/DROP/ {s+=$1} END {print s+0}'; }
C0=$(drop_count)
ip netns exec nsB "$PY" - <<'PYEOF' 2>/dev/null || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.99.0.2", 0))  # probe from the BLOCKED address
for _ in range(5):
    s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
             ("10.99.0.1", 53))
PYEOF
sleep 2
C1=$(drop_count)
echo "DROP-rule packet counter: $C0 -> $C1 (delta $((C1-C0)); >=4 proves the block drops nsB traffic at the IP layer while AF_PACKET capture keeps observing)"

say "7e. EVIDENCE — syslog/SIEM alert lines (journal)"
if command -v journalctl >/dev/null 2>&1; then
    journalctl --no-pager -t exfiltrap -n 4 2>/dev/null || \
        echo "(no journal records — syslog tag routing differs on this host)"
else
    echo "(journalctl unavailable; alert lines went to /dev/log)"
fi

say "8. teardown"
kill "$SVC_PID" "$BEN_PID" "$DRIP_PID" "$UI_PID" 2>/dev/null || true
# Belt and braces: `kill` above can miss wrapper/orphaned children
# (a leftover root service holding the DB open breaks the next run).
pkill -f "exfiltrap.service" 2>/dev/null || true
pkill -f "benign_traffic_gen" 2>/dev/null || true
pkill -f "attacker_client" 2>/dev/null || true
pkill -f "exfiltrap.dashboard" 2>/dev/null || true
sleep 3
# SIGTERM now unwinds the service (fixed); -9 only if something still hangs.
pkill -9 -f "exfiltrap.service --iface" 2>/dev/null || true
sleep 2
chown "$RUN_USER": "$REPO/data/live.db"* 2>/dev/null || true
"$REPO/tools/netns_teardown.sh"
echo
echo "=== live deployment finished — $(date) ==="
