#!/usr/bin/env bash
set -euo pipefail

# ---------- options ----------
REBOOT=${REBOOT:-0}
# parse args (simple)
for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --help|-h) echo "Usage: $0 [--reboot]"; exit 0 ;;
    *) ;; # ignore unknown
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }

# ---------- figure out target non-root user ----------
resolve_user() {
  # prefer the invoking sudo user, else any real user (uid>=1000)
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '%s' "$SUDO_USER"; return
  fi
  # try logname
  if logname >/dev/null 2>&1; then
    ln=$(logname 2>/dev/null || true)
    if [ -n "$ln" ] && [ "$ln" != "root" ]; then
      printf '%s' "$ln"; return
    fi
  fi
  # fallback: first non-system user in /etc/passwd
  awk -F: '$3>=1000 && $1!="nobody" { print $1; exit }' /etc/passwd
}
USERNAME="$(resolve_user)"
if [ -z "$USERNAME" ]; then
  echo "ERROR: could not resolve a non-root user. Run this script with sudo from your user account." >&2
  exit 1
fi
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)

log "Target user: $USERNAME (home: $HOME_DIR)"

# ---------- 1) install openssh + dconf ----------
log "1) Install OpenSSH and dconf-cli"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server dconf-cli

systemctl enable --now ssh || true

# open firewall for SSH if ufw active
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow OpenSSH || true
fi

# ---------- 2) GNOME system-wide: disable idle/lock/suspend (dconf) ----------
# Use /etc/dconf/db/local.d and locks so it is system-wide and idempotent.
log "2) Apply system-wide GNOME dconf defaults (disable idle/lock/suspend)"
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
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/gnome/settings-daemon/plugins/power/idle-dim
EOF

# compile/update dconf DB
dconf update || true

# ---------- 3) GDM greeter (login screen) dconf ----------
log "3) Prevent GDM greeter from blanking/suspending"
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

dconf update || true

# ---------- 4) mask systemd sleep targets ----------
log "4) Mask systemd sleep targets (prevent suspend/hibernate)"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target || true

# ---------- 5) make logind ignore lid/power keys ----------
log "5) Configure systemd-logind to ignore lid/suspend keys"
conf=/etc/systemd/logind.conf
touch "$conf"
# replace or append values idempotently
sed -i \
  -e 's/^[#[:space:]]*HandleSuspendKey=.*/HandleSuspendKey=ignore/' \
  -e 's/^[#[:space:]]*HandleHibernateKey=.*/HandleHibernateKey=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitch=.*/HandleLidSwitch=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' \
  "$conf" || true
grep -q '^IdleAction=ignore' "$conf" || echo 'IdleAction=ignore' >>"$conf"
systemctl restart systemd-logind || true

# ---------- 6) Disable console (TTY) blanking ----------
log "6) Disable TTY console blanking (systemd oneshot service)"
cat >/etc/systemd/system/disable-console-blanking.service <<'EOF'
[Unit]
Description=Disable TTY console blanking
After=getty.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for t in /dev/tty[1-12]; do /usr/bin/setterm -term linux -blank 0 -powersave off -powerdown 0 >"$t" <"$t" || true; done'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now disable-console-blanking.service || true

# ---------- 7) Disable Wi-Fi powersave (NetworkManager) ----------
log "7) Disable Wi-Fi power save (NetworkManager drop-in)"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
# 2 = disable Wi-Fi power saving
wifi.powersave=2
EOF

if systemctl is-active --quiet NetworkManager 2>/dev/null || systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
  systemctl restart NetworkManager || true
fi

# ---------- 8) Optional: key-only SSH if SSH_KEY_PATH provided ----------
if [ "${SSH_KEY_PATH:-}" != "" ] && [ -f "${SSH_KEY_PATH}" ]; then
  log "8) Install SSH public key for $USERNAME (idempotent)"
  AUTH_DIR="$HOME_DIR/.ssh"
  AUTH_FILE="$AUTH_DIR/authorized_keys"
  install -d -m 0700 -o "$USERNAME" -g "$USERNAME" "$AUTH_DIR"
  touch "$AUTH_FILE"
  chown "$USERNAME":"$USERNAME" "$AUTH_FILE"
  chmod 600 "$AUTH_FILE"
  KEY_CONTENT="$(cat "$SSH_KEY_PATH")"
  if ! grep -qxF "$KEY_CONTENT" "$AUTH_FILE"; then
    echo "$KEY_CONTENT" >>"$AUTH_FILE"
  fi

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

# ---------- 9) Enable GDM automatic login for the resolved user ----------
log "9) Enable GDM automatic login for user: $USERNAME"
GDM_CONF="/etc/gdm3/custom.conf"
install -d -m 0755 /etc/gdm3
# Ensure file exists
touch "$GDM_CONF"

# Ensure a [daemon] section exists
if ! grep -q '^\[daemon\]' "$GDM_CONF"; then
  printf '\n[daemon]\n' >>"$GDM_CONF"
fi

# Replace or insert AutomaticLoginEnable and AutomaticLogin inside [daemon]
awk -v user="$USERNAME" '
BEGIN{in_d=0; set_enable=0; set_user=0}
{
  if ($0 ~ /^\[daemon\]/) { print; in_d=1; next }
  if (in_d && $0 ~ /^\[/) { # leaving [daemon]
     if (!set_enable) print "AutomaticLoginEnable=true"
     if (!set_user) print "AutomaticLogin=" user
     in_d=0
  }
  if (in_d) {
     if ($0 ~ /^[[:space:]]*AutomaticLoginEnable[[:space:]]*=/) { print "AutomaticLoginEnable=true"; set_enable=1; next }
     if ($0 ~ /^[[:space:]]*AutomaticLogin[[:space:]]*=/) { print "AutomaticLogin=" user; set_user=1; next }
  }
  print
}
END {
  if (in_d) {
    if (!set_enable) print "AutomaticLoginEnable=true"
    if (!set_user) print "AutomaticLogin=" ENVIRON["USERNAME"]
  }
}' USERNAME="$USERNAME" "$GDM_CONF" > "$GDM_CONF.tmp" && mv "$GDM_CONF.tmp" "$GDM_CONF" || true

# ---------- 10) Reset GNOME keyring (remove login keyring) ----------
log "10) Reset GNOME keyring for $USERNAME (removes ~/.local/share/keyrings/login.keyring)"
KEYRINGS_DIR="$HOME_DIR/.local/share/keyrings"
if [ -d "$KEYRINGS_DIR" ] && ls -A "$KEYRINGS_DIR" >/dev/null 2>&1; then
  TS=$(date +%Y%m%d-%H%M%S)
  BACKUP_DIR="$HOME_DIR/.local/share/keyrings-backup-$TS"
  cp -a "$KEYRINGS_DIR" "$BACKUP_DIR" || true
  chown -R "$USERNAME":"$USERNAME" "$BACKUP_DIR" || true
fi
mkdir -p "$KEYRINGS_DIR"
# Remove the typical keyring files that cause the login prompt; safe to repeat
rm -f "$KEYRINGS_DIR/login.keyring" "$KEYRINGS_DIR/user.keystore" "$KEYRINGS_DIR/*.keyring" || true
chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.local" || true

cat >/etc/issue.keyring-note <<'EOF'
NOTE: The GNOME keyring was reset. On next login, if a prompt asks to create a "Login" keyring,
leave the password blank if you want it to unlock automatically with auto-login (this stores
secrets unencrypted). See your security policy before doing so.
EOF

# ---------- final: reboot optionally ----------
if [ "$REBOOT" -eq 1 ]; then
  log "Final: reboot requested. Rebooting now..."
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested. To apply some changes (GDM/dconf) please log out and back in, or reboot manually."
  echo "If you'd like to reboot now: sudo systemctl reboot"
fi

exit 0
