#!/usr/bin/env bash
# ExfilTrap Linux uninstaller — inverse of install_linux.sh.
set -euo pipefail

IFACE="${1:-}"
if [[ ${EUID} -ne 0 ]]; then
    echo "run with sudo"; exit 1
fi
if [[ -n "$IFACE" ]] && systemctl is-active "exfiltrap@$IFACE" &>/dev/null; then
    systemctl stop "exfiltrap@$IFACE"
fi
systemctl disable "exfiltrap@.service" 2>/dev/null || true
rm -f /etc/systemd/system/exfiltrap@.service
systemctl daemon-reload
rm -rf /opt/exfiltrap
# Keep /var/lib/exfiltrap unless asked otherwise (it holds history).
id exfiltrap &>/dev/null && userdel exfiltrap || true
echo "ExfilTrap removed (database kept at /var/lib/exfiltrap — delete manually if desired)."
