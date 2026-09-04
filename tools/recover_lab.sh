#!/usr/bin/env bash
# One-shot recovery: kill any stuck ExFilTrap lab processes + teardown.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ${EUID} -ne 0 ]]; then
    ASKPASS="$REPO/tools/.recover_askpass.sh"
    printf '#!/bin/bash\nexec zenity --password --title="ExFilTrap recovery needs sudo" 2>/dev/null\n' > "$ASKPASS"
    chmod 700 "$ASKPASS"
    export SUDO_ASKPASS="$ASKPASS"
    exec sudo -A -E bash "$0" "$@"
fi
rm -f "$REPO/tools/.recover_askpass.sh"

pkill -f "bash tools/stress_test.sh$" 2>/dev/null && echo "killed stuck stress driver" || true
pkill -9 -f "exfiltrap.service" 2>/dev/null && echo "killed service" || true
pkill -f "stress_traffic" 2>/dev/null || true
sleep 2
"$REPO/tools/netns_teardown.sh" || true
echo "recovery complete"
