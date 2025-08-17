#!/usr/bin/env bash
set -euo pipefail

log() { printf '\n=== %s ===\n' "$*"; }

log "[1/8] Install OpenSSH server + dconf tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server dconf-cli
systemctl enable --now ssh

# If UFW is installed and active, allow OpenSSH (safe to repeat)
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow OpenSSH || true
  fi
fi

log "[2/8] System-wide GNOME defaults: disable idle/lock/suspend"
install -d -m 0755 /etc/dconf/db/local.d
cat >/etc/dconf/db/local.d/00-nosleep <<'EOF'
[org/gnome/desktop/session]
# 0 means "never" — must include uint32
idle-delay=uint32 0

[org/gnome/desktop/screensaver]
lock-enabled=false
idle-activation-enabled=false

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='nothing'
sleep-inactive-ac-timeout=0
sleep-inactive-battery-type='nothing'
sleep-inactive-battery-timeout=0
idle-dim=false
EOF

# Lock key settings so per-user changes can't override them (optional but useful)
install -d -m 0755 /etc/dconf/db/local.d/locks
cat >/etc/dconf/db/local.d/locks/00-nosleep-locks <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/gnome/settings-daemon/plugins/power/idle-dim
EOF

dconf update

log "[3/8] GDM (login screen) settings: disable blanking/suspend"
install -d -m 0755 /etc/dconf/profile
cat >/etc/dconf/profile/gdm <<'EOF'
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

install -d -m 0755 /etc/dconf/db/gdm.d
cat >/etc/dconf/db/gdm.d/00-nosleep <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 0

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='nothing'
sleep-inactive-battery-type='nothing'
idle-dim=false
EOF

dconf update

log "[4/8] Block suspend/hibernate at the systemd level"
# Safe to repeat; masks just (re)point unit links to /dev/null
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target || true

log "[5/8] Make logind ignore lid/suspend actions"
# Update or insert desired values; repeated runs are safe
conf=/etc/systemd/logind.conf
touch "$conf"
sed -i \
  -e 's/^[#[:space:]]*HandleSuspendKey=.*/HandleSuspendKey=ignore/' \
  -e 's/^[#[:space:]]*HandleHibernateKey=.*/HandleHibernateKey=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitch=.*/HandleLidSwitch=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' \
  "$conf"
grep -q '^IdleAction=ignore' "$conf" || echo 'IdleAction=ignore' >>"$conf"
systemctl restart systemd-logind || true

log "[6/8] Disable console (TTY) blanking on boot"
cat >/etc/systemd/system/disable-console-blanking.service <<'EOF'
[Unit]
Description=Disable TTY console blanking
After=getty.target

[Service]
Type=oneshot
# Apply to the usual VTs; harmless if some don't exist
ExecStart=/bin/sh -c 'for t in /dev/tty[1-12]; do /usr/bin/setterm -term linux -blank 0 -powersave off -powerdown 0 >"$t" <"$t" || true; done'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now disable-console-blanking.service

log "[7/8] Disable Wi-Fi powersave (NetworkManager)"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
# 2 = DISABLE Wi-Fi power saving
wifi.powersave=2
EOF
# Restart NM only if present/active
if systemctl is-enabled --quiet NetworkManager 2>/dev/null || systemctl is-active --quiet NetworkManager 2>/dev/null; then
  systemctl restart NetworkManager || true
fi

log "[8/8] Optional: set up key-only SSH if SSH_KEY_PATH is provided"
if [ "${SSH_KEY_PATH:-}" != "" ] && [ -f "$SSH_KEY_PATH" ]; then
  USERNAME="${SUDO_USER:-${LOGNAME:-$USER}}"
  HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
  AUTH_DIR="$HOME_DIR/.ssh"
  AUTH_FILE="$AUTH_DIR/authorized_keys"

  install -d -m 0700 -o "$USERNAME" -g "$USERNAME" "$AUTH_DIR"
  touch "$AUTH_FILE"
  chown "$USERNAME":"$USERNAME" "$AUTH_FILE"
  chmod 600 "$AUTH_FILE"

  KEY_CONTENT="$(cat "$SSH_KEY_PATH")"
  # Append only if the exact key line is not present
  if ! grep -qxF "$KEY_CONTENT" "$AUTH_FILE"; then
    echo "$KEY_CONTENT" >>"$AUTH_FILE"
  fi

  # Configure sshd to refuse passwords (safe to overwrite each run)
  install -d /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/90-key-only.conf <<'EOF'
# Enforce public-key auth only
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
  systemctl reload ssh || true
fi

echo
echo "Done. If you had a desktop session running, log out/in (or reboot) once for GNOME/GDM dconf defaults to fully apply."
