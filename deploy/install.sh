#!/usr/bin/env bash
# ROB VPS install. Idempotent: safe to re-run after a git pull.
#
# Creates a dedicated unprivileged user, installs a systemd service for the
# console and a timer for the nightly scan, and binds the console to localhost.
# The console is NOT exposed to the internet by this script: reach it over an
# SSH tunnel or a private mesh. It has one shared password and no TLS, which is
# fine on loopback and not fine on a public interface.
set -euo pipefail

ROB_USER="${ROB_USER:-rob}"
ROB_HOME="${ROB_HOME:-/opt/rob}"
ROB_DATA="${ROB_DATA:-/var/lib/rob}"
SCAN_TIME="${SCAN_TIME:-02:30}"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0"; exit 1; }; }
need_root

command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 - <<'PY' || { echo "ROB needs Python 3.10 or newer, found $PYV"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

id -u "$ROB_USER" >/dev/null 2>&1 || useradd --system --home-dir "$ROB_DATA" --shell /usr/sbin/nologin "$ROB_USER"
install -d -o "$ROB_USER" -g "$ROB_USER" -m 750 "$ROB_DATA"
install -d -m 755 "$ROB_HOME"

if [ ! -f "$ROB_HOME/rob/__init__.py" ]; then
  echo "Copy the ROB source to $ROB_HOME first (git clone or rsync), then re-run."
  exit 1
fi
chown -R root:root "$ROB_HOME"   # code is read-only to the service user

cat > /etc/systemd/system/rob-console.service <<UNIT
[Unit]
Description=ROB console (Remediation and Optimisation Bot)
After=network-online.target

[Service]
Type=simple
User=$ROB_USER
WorkingDirectory=$ROB_HOME
ExecStart=/usr/bin/python3 -m rob serve --home $ROB_DATA --host 127.0.0.1 --port 8422
Restart=on-failure
RestartSec=5
# Loopback only. Exposing this needs TLS and real user accounts first.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$ROB_DATA

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/rob-scan.service <<UNIT
[Unit]
Description=ROB scheduled scan
After=network-online.target

[Service]
Type=oneshot
User=$ROB_USER
WorkingDirectory=$ROB_HOME
EnvironmentFile=-$ROB_DATA/scan.env
ExecStart=/usr/bin/python3 -m rob scheduled-scan --home $ROB_DATA \$ROB_SCAN_ARGS
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$ROB_DATA
UNIT

cat > /etc/systemd/system/rob-scan.timer <<UNIT
[Unit]
Description=Nightly ROB scan

[Timer]
OnCalendar=*-*-* $SCAN_TIME:00
# Spread load and survive a reboot at the wrong moment
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
UNIT

if [ ! -f "$ROB_DATA/scan.env" ]; then
  cat > "$ROB_DATA/scan.env" <<ENV
# Credentials for the scheduled scan. A scheduled job must never prompt.
ROB_SN_PASSWORD=
ROB_SCAN_ARGS=--instance https://devXXXXX.service-now.com --user rob.integration
ENV
  chown "$ROB_USER:$ROB_USER" "$ROB_DATA/scan.env"
  chmod 600 "$ROB_DATA/scan.env"
fi

systemctl daemon-reload
systemctl enable --now rob-console.service
systemctl enable --now rob-scan.timer

cat <<DONE

ROB installed.

  Console   http://127.0.0.1:8422   (loopback only, by design)
  Data      $ROB_DATA
  Schedule  $SCAN_TIME nightly, +/- 15 min jitter

Next:
  1. Put the instance credential in $ROB_DATA/scan.env and set ROB_SCAN_ARGS
  2. Add a notify block to $ROB_DATA/web_config.json (see deploy/notify.example.json)
  3. Reach the console from your laptop:
       ssh -N -L 8422:127.0.0.1:8422 you@this-host
  4. Test the scan once by hand:
       systemctl start rob-scan.service && journalctl -u rob-scan -n 40 --no-pager

Do NOT put the console on a public interface until it has TLS and per-user accounts.
DONE
