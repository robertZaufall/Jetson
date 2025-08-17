#!/usr/bin/env bash
set -euo pipefail

echo "[1/7] Install & enable OpenSSH server…"
apt-get update -y
apt-get install -y openssh-server dconf-cli
systemctl enable --now ssh

# If UFW is installed and active, open SSH.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow OpenSSH || true
fi

echo "[2/7] Disable desktop screen blanking, lock & auto-suspend (system-wide defaults)…"
install -d -m 0755 /etc/dconf/db/local.d
cat >/etc/dconf/db/local.d/00-nosleep <<'EOF'
[org/gnome/desktop/session]
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

install -d -m 0755 /etc/dconf/db/local.d/locks
cat >/etc/dconf/db/local.d/locks/00-nosleep-locks <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
EOF

dconf update

echo "[3/7] Disable blanking/suspend on the GDM login screen…"
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

echo "[4/7] Block all system sleep targets at the systemd level…"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

echo "[5/7] Tell logind to ignore lid/power sleep triggers…"
# Edit (or append) logind.conf safely
sed -i -e 's/^[#]*\s*HandleSuspendKey=.*/HandleSuspendKey=ignore/' \
       -e 's/^[#]*\s*HandleHibernateKey=.*/HandleHibernateKey=ignore/' \
       -e 's/^[#]*\s*HandleLidSwitch=.*/HandleLidSwitch=ignore/' \
       -e 's/^[#]*\s*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' \
       -e 's/^[#]*\s*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' \
       /etc/systemd/logind.conf || true
grep -q '^IdleAction=ignore' /etc/systemd/logind.conf || echo 'IdleAction=ignore' >> /etc/systemd/logind.conf
systemctl restart systemd-logind || true

echo "[6/7] Disable console (tty) blanking on boot…"
cat >/etc/systemd/system/disable-console-blanking.service <<'EOF'
[Unit]
Description=Disable TTY console blanking
After=getty.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for t in /dev/tty[1-6]; do /usr/bin/setterm -term linux -blank 0 -powersave off -powerdown 0 >$t <$t; done'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now disable-console-blanking.service

echo "[7/7] Disable Wi-Fi power saving (NetworkManager)…"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
wifi.powersave=2
EOF
systemctl restart NetworkManager || true

# Optional: Key-only SSH hardening when SSH_KEY_PATH is provided
if [ "${SSH_KEY_PATH:-}" != "" ] && [ -f "$SSH_KEY_PATH" ]; then
  USERNAME="${SUDO_USER:-${LOGNAME:-$USER}}"
  install -d -m 0700 -o "$USERNAME" -g "$USERNAME" "/home/$USERNAME/.ssh"
  cat "$SSH_KEY_PATH" >>"/home/$USERNAME/.ssh/authorized_keys"
  chown "$USERNAME":"$USERNAME" "/home/$USERNAME/.ssh/authorized_keys"
  chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

  cat >/etc/ssh/sshd_config.d/90-key-only.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
  systemctl reload ssh
fi

echo "All set. Log out/in (or reboot) for GNOME dconf defaults to fully apply."
