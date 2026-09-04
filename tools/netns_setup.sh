#!/usr/bin/env bash
# ExfilTrap lab: isolated network namespace pair (spec Section 4).
# nsA = gateway/detector (10.99.0.1), nsB = attacker (10.99.0.2).
# iptables rules applied inside nsA never touch the host firewall.
set -euo pipefail

SUDO=""
if [[ ${EUID} -ne 0 ]]; then
    SUDO="sudo"
fi

for ns in nsA nsB; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        echo "namespace $ns already exists — recreating"
        $SUDO ip netns del "$ns"
    fi
done

$SUDO ip netns add nsA
$SUDO ip netns add nsB

$SUDO ip link add veth-gw type veth peer name veth-atk
$SUDO ip link set veth-gw netns nsA
$SUDO ip link set veth-atk netns nsB

$SUDO ip netns exec nsA ip addr add 10.99.0.1/24 dev veth-gw
$SUDO ip netns exec nsB ip addr add 10.99.0.2/24 dev veth-atk
# Second address for the benign background (.3): per-session detection
# (mass z-test, beacon) keys on src_ip, so separating benign and attacker
# roles by address lets the stateful layer see the drip as its own session.
$SUDO ip netns exec nsB ip addr add 10.99.0.3/24 dev veth-atk

$SUDO ip netns exec nsA ip link set veth-gw up
$SUDO ip netns exec nsB ip link set veth-atk up
$SUDO ip netns exec nsA ip link set lo up
$SUDO ip netns exec nsB ip link set lo up

echo "Namespaces ready: nsA=10.99.0.1 (gateway), nsB=10.99.0.2 (attacker)"
echo ""
echo "Run the detector inside nsA:"
echo "  sudo ip netns exec nsA python3 -m exfiltrap.pipeline --iface veth-gw"
echo "Run the attacker inside nsB:"
echo "  sudo ip netns exec nsB python3 tools/attacker_client.py --target 10.99.0.1 --mode slow-drip"
echo ""
echo "Teardown: ./tools/netns_teardown.sh"
