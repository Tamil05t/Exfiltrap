#!/usr/bin/env bash
# ExfilTrap Linux installer.
#
# Runs ONCE with sudo (the only elevated moment in the product's life):
#   ./tools/install_linux.sh eth0
#
# What it does:
#   1. copies the project to /opt/exfiltrap and builds its venv
#   2. creates a locked-down service user
#   3. installs the systemd template unit — the daemon then runs as that
#      user with ONLY CAP_NET_RAW/CAP_NET_ADMIN (never root), surviving
#      reboots, exactly like any other system service
#   4. trains the model if no artifact exists yet
#
# Afterwards: systemctl start exfiltrap@<iface>, dashboard on
# http://127.0.0.1:5050 — no sudo needed for daily use.
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
    echo "usage: $0 <network-interface>   (e.g. $0 eth0)"; exit 1
fi
if [[ ${EUID} -ne 0 ]]; then
    echo "this installer must run once with sudo"; exit 1
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/opt/exfiltrap
DATA=/var/lib/exfiltrap

echo "== installing ExfilTrap to $DEST"
mkdir -p "$DEST" "$DATA"
rsync -a --exclude .venv --exclude .git --exclude __pycache__ \
      --exclude .pytest_cache "$SRC"/ "$DEST"/

echo "== service user (system account, no login, no home shell)"
if ! id exfiltrap &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin exfiltrap
fi
chown -R exfiltrap:exfiltrap "$DATA"

echo "== python environment"
if [[ ! -x "$DEST/.venv/bin/python" ]]; then
    python3 -m venv "$DEST/.venv"
fi
"$DEST/.venv/bin/pip" install --quiet --upgrade pip
"$DEST/.venv/bin/pip" install --quiet -r "$DEST/requirements.txt"

echo "== detection model"
if [[ ! -f "$DEST/data/model/rf_model.joblib" ]]; then
    (cd "$DEST" && .venv/bin/python tools/train_classifier.py)
fi

echo "== systemd unit"
install -m 644 "$DEST/packaging/linux/exfiltrap@.service" \
        /etc/systemd/system/exfiltrap@.service
systemctl daemon-reload
systemctl enable "exfiltrap@$IFACE"

echo
echo "Installed. Start it (once) with:"
echo "  sudo systemctl start exfiltrap@$IFACE"
echo "Dashboard/API: http://127.0.0.1:5050"
echo "Enable live firewall mitigation via a drop-in:"
echo "  sudo systemctl edit exfiltrap@$IFACE"
echo "    [Service]"
echo "    Environment=EXFILTRAP_MITIGATION=iptables"
echo "    Environment=EXFILTRAP_EXECUTE=1"
echo "Uninstall: $DEST/tools/uninstall_linux.sh $IFACE"
