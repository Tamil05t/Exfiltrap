#!/usr/bin/env bash
# Remove the ExfilTrap lab namespaces and any leftover veth links.
set -euo pipefail

SUDO=""
if [[ ${EUID} -ne 0 ]]; then
    SUDO="sudo"
fi

for ns in nsA nsB; do
    if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
        $SUDO ip netns del "$ns"
        echo "deleted namespace $ns"
    else
        echo "namespace $ns not present"
    fi
done

for link in veth-gw veth-atk; do
    if ip link show "$link" >/dev/null 2>&1; then
        $SUDO ip link del "$link"
        echo "deleted leftover link $link"
    fi
done

echo "lab teardown complete"
