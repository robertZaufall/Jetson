#!/usr/bin/env bash

set -euo pipefail

REBOOT=${REBOOT:-0}
for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --vnc-backend=*) VNC_BACKEND="${arg#*=}" ;;
    --vnc-no-encryption|--vnc-insecure) VNC_NO_ENCRYPTION=1 ;;
    --vnc-password=*|--vnc-pass=*) VNC_PASSWORD="${arg#*=}" ;;
    --hostname=*|--set-hostname=*) NEW_HOSTNAME="${arg#*=}" ;;
    --swap-size=*) SWAP_SIZE="${arg#*=}" ;;
    --help|-h) echo "Usage: $0 [--reboot] [--vnc-backend=grd|x11vnc] [--vnc-password=PASS] [--vnc-no-encryption] [--hostname=NAME] [--swap-size=SIZE] [SSH_KEY_PATH=...]" ; exit 0 ;;
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }
VNC_BACKEND=${VNC_BACKEND:-grd}
VNC_NO_ENCRYPTION=${VNC_NO_ENCRYPTION:-0}
SWAP_SIZE=${SWAP_SIZE:-8G}

resolve_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  if logname >/dev/null 2>&1; then ln=$(logname 2>/dev/null || true); [ -n "$ln" ] && [ "$ln" != "root" ] && { printf '%s' "$ln"; return; }; fi
  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}
USERNAME="$(resolve_user)"
[ -n "$USERNAME" ] || { echo "ERROR: could not resolve a non-root user." >&2; exit 1; }
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"

log "1) Install OpenSSH + dconf tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server dconf-cli nano btop curl git-lfs
git lfs install --system || true
systemctl enable --now ssh || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow OpenSSH || true; fi

log "2) GNOME system-wide: disable idle/lock/suspend (dconf)"
# Ensure the dconf user profile reads system 'local' DB (required for defaults to apply)
install -d -m 0755 /etc/dconf/profile
if [ ! -f /etc/dconf/profile/user ] || ! grep -Pq '^\s*user-db:user' /etc/dconf/profile/user || ! grep -Pq '^\s*system-db:local' /etc/dconf/profile/user; then
  cat >/etc/dconf/profile/user <<'EOF'
user-db:user
system-db:local
EOF
fi
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
dconf update || true

log "3) GDM greeter: prevent idle/suspend"
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

log "4) X11 PERMANENT: disable DPMS & blanking at the Xorg level"
install -d -m 0755 /etc/X11/xorg.conf.d
cat >/etc/X11/xorg.conf.d/10-extensions.conf <<'EOF'
Section "Extensions"
    Option "DPMS" "false"
EndSection
EOF
cat >/etc/X11/xorg.conf.d/10-serverflags.conf <<'EOF'
Section "ServerFlags"
    Option "BlankTime" "0"
    Option "StandbyTime" "0"
    Option "SuspendTime" "0"
    Option "OffTime" "0"
EndSection
EOF

log "5) X11 PERMANENT: user-session fallback to enforce no-blank via xset"
cat >/usr/local/bin/disable-dpms-x11 <<'EOF'
#!/bin/sh
# Run only for X11 sessions
[ "$XDG_SESSION_TYPE" = "x11" ] || exit 0
# Disable X screensaver and DPMS in the running session
command -v xset >/dev/null 2>&1 || exit 0
xset s off
xset s noblank
xset -dpms
exit 0
EOF
chmod +x /usr/local/bin/disable-dpms-x11
install -d -m 0755 /etc/xdg/autostart
cat >/etc/xdg/autostart/99-x11-noblank.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Disable X11 screen blanking
Exec=/usr/local/bin/disable-dpms-x11
X-GNOME-Autostart-enabled=true
EOF

log "6) Block suspend/hibernate at systemd level"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target || true

log "7) systemd-logind: ignore lid/suspend keys"
conf=/etc/systemd/logind.conf
touch "$conf"
sed -i \
  -e 's/^[#[:space:]]*HandleSuspendKey=.*/HandleSuspendKey=ignore/' \
  -e 's/^[#[:space:]]*HandleHibernateKey=.*/HandleHibernateKey=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitch=.*/HandleLidSwitch=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' \
  -e 's/^[#[:space:]]*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' \
  "$conf" || true
grep -q '^IdleAction=ignore' "$conf" || echo 'IdleAction=ignore' >>"$conf"
systemctl restart systemd-logind || true

log "8) Disable TTY (virtual console) blanking"
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

log "9) Disable Wi-Fi powersave (NetworkManager)"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
wifi.powersave=2
EOF
if systemctl is-active --quiet NetworkManager 2>/dev/null || systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
  systemctl restart NetworkManager || true
fi

log "10) Optional: key-only SSH (if SSH_KEY_PATH provided)"
if [ "${SSH_KEY_PATH:-}" != "" ] && [ -f "${SSH_KEY_PATH}" ]; then
  AUTH_DIR="$HOME_DIR/.ssh"; AUTH_FILE="$AUTH_DIR/authorized_keys"
  install -d -m 0700 -o "$USERNAME" -g "$USERNAME" "$AUTH_DIR"
  touch "$AUTH_FILE"; chown "$USERNAME":"$USERNAME" "$AUTH_FILE"; chmod 600 "$AUTH_FILE"
  KEY_CONTENT="$(cat "$SSH_KEY_PATH")"
  grep -qxF "$KEY_CONTENT" "$AUTH_FILE" || echo "$KEY_CONTENT" >>"$AUTH_FILE"
  install -d /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/90-key-only.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
  systemctl reload ssh || true
fi

log "11) Enable GDM auto-login for user: $USERNAME"
GDM_CONF="/etc/gdm3/custom.conf"
install -d -m 0755 /etc/gdm3
touch "$GDM_CONF"
grep -q '^\[daemon\]' "$GDM_CONF" || printf '\n[daemon]\n' >> "$GDM_CONF"
awk -v user="$USERNAME" '
BEGIN{in_d=0; se=0; su=0; sw=0}
{
  if ($0 ~ /^\[daemon\]/){in_d=1; print; next}
  if (in_d && $0 ~ /^\[/){ if(!se) print "AutomaticLoginEnable=true"; if(!su) print "AutomaticLogin=" user; if(!sw) print "WaylandEnable=false"; in_d=0 }
  if (in_d){
    if ($0 ~ /^[#[:space:]]*AutomaticLoginEnable[[:space:]]*=/){print "AutomaticLoginEnable=true"; se=1; next}
    if ($0 ~ /^[#[:space:]]*AutomaticLogin[[:space:]]*=/){print "AutomaticLogin=" user; su=1; next}
    if ($0 ~ /^[#[:space:]]*WaylandEnable[[:space:]]*=/){print "WaylandEnable=false"; sw=1; next}
  }
  print
}
END{ if(in_d){ if(!se) print "AutomaticLoginEnable=true"; if(!su) print "AutomaticLogin=" user; if(!sw) print "WaylandEnable=false" } }
' "$GDM_CONF" > "$GDM_CONF.tmp" && mv "$GDM_CONF.tmp" "$GDM_CONF"

log "12) Create default UNENCRYPTED GNOME keyring (no UI prompts)"
KEYRINGS_DIR="$HOME_DIR/.local/share/keyrings"
mkdir -p "$KEYRINGS_DIR"

# Backup any existing keyrings once (timestamped)
if ls -A "$KEYRINGS_DIR" >/dev/null 2>&1; then
  TS=$(date +%Y%m%d-%H%M%S)
  BACKUP_DIR="$HOME_DIR/.local/share/keyrings-backup-$TS"
  cp -a "$KEYRINGS_DIR" "$BACKUP_DIR" || true
  chown -R "$USERNAME":"$USERNAME" "$BACKUP_DIR" || true
fi

# Define an unencrypted default keyring named "Default_keyring"
DEFAULT_POINTER_FILE="$KEYRINGS_DIR/default"
DEFAULT_RING_FILE="$KEYRINGS_DIR/Default_keyring.keyring"

# Point the default file to our unencrypted keyring
echo -n "Default_keyring" > "$DEFAULT_POINTER_FILE"

# Create a minimal unencrypted keyring file (plaintext format)
cat >"$DEFAULT_RING_FILE" <<'EOF'
[keyring]
display-name=Default keyring
ctime=0
mtime=0
lock-on-idle=false
lock-after=false
EOF

# Tighten permissions and ownership
chmod 700 "$KEYRINGS_DIR" || true
chmod 600 "$DEFAULT_RING_FILE" || true
chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.local" || true

# Remove any leftover encrypted login keyring files that could trigger prompts
rm -f "$KEYRINGS_DIR/login.keyring" "$KEYRINGS_DIR/user.keystore" 2>/dev/null || true

cat >/etc/issue.keyring-note <<'EOF'
NOTE: Keyring configured for **unsafe storage**. A plaintext keyring was created and set as default,
so GNOME will not prompt to set a keyring password. Secrets stored via libsecret/gnome-keyring are
unencrypted on disk. Change this policy if you need encryption.
EOF


if [ -n "${VNC_PASSWORD:-}" ]; then
  log "13) VNC / Remote Desktop server setup (backend: ${VNC_BACKEND})"
  USER_UID=$(id -u "$USERNAME")
  USER_ENV=("XDG_RUNTIME_DIR=/run/user/${USER_UID}" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${USER_UID}/bus")

  if [ "${VNC_BACKEND}" = "grd" ]; then
    # --- GNOME Remote Desktop (VNC) ---
    apt-get install -y gnome-remote-desktop libsecret-tools || true

    if command -v grdctl >/dev/null 2>&1; then
      sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc enable || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc set-auth-method password || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc disable-view-only || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc set-password "$VNC_PASSWORD" || true
      if [ "${VNC_NO_ENCRYPTION}" -eq 1 ]; then
        sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true
      fi
      loginctl enable-linger "$USERNAME" || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop.service || true
    else
      # Fallback to gsettings + secret-tool
      sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc auth-method 'password' || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc view-only false || true
      if [ "${VNC_NO_ENCRYPTION}" -eq 1 ]; then
        sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true
      fi
      printf '%s' "$VNC_PASSWORD" | sudo -u "$USERNAME" env "${USER_ENV[@]}" secret-tool store --label="GNOME Remote Desktop VNC password" xdg:schema org.gnome.RemoteDesktop.VncPassword || true
      loginctl enable-linger "$USERNAME" || true
      sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop.service || true
    fi

    # Avoid port conflicts with legacy x11vnc
    systemctl disable --now x11vnc.service 2>/dev/null || true

  else
    # --- Legacy x11vnc backend (shares X11 :0) ---
    apt-get install -y x11vnc || true

    # Always (re)set password when provided
    echo "$VNC_PASSWORD" | x11vnc -storepasswd stdin /etc/x11vnc.pass >/dev/null 2>&1 || true
    chmod 600 /etc/x11vnc.pass && chown root:root /etc/x11vnc.pass

    cat >/etc/systemd/system/x11vnc.service <<'EOF'
[Unit]
Description=Legacy VNC server for X11 (x11vnc)
Requires=display-manager.service
After=display-manager.service graphical.target

[Service]
Type=simple
Environment=DISPLAY=:0
ExecStartPre=/bin/sh -c 'for i in $(seq 1 120); do [ -S /tmp/.X11-unix/X0 ] && exit 0; sleep 1; done; exit 1'
ExecStart=/usr/bin/x11vnc -display :0 -auth guess -forever -loop -noxdamage -repeat -rfbauth /etc/x11vnc.pass -rfbport 5900 -shared -o /var/log/x11vnc.log
Restart=always
RestartSec=2

[Install]
WantedBy=graphical.target
EOF

    systemctl daemon-reload
    systemctl enable --now x11vnc.service || true

    # Stop GNOME Remote Desktop to avoid port conflict
    sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user disable --now gnome-remote-desktop.service 2>/dev/null || true
  fi

  # Open firewall for VNC
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 5900/tcp || true
  fi
else
  log "13) VNC setup skipped (no --vnc-password provided)"
fi

log "14) Rename device (hostname) if requested"
if [ -n "${NEW_HOSTNAME:-}" ]; then
  # Validate hostname (RFC 1123 label rules: letters/digits/hyphen; max 63 per label)
  if ! echo "$NEW_HOSTNAME" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'; then
    echo "ERROR: --hostname must be a valid RFC1123 hostname (letters, digits, hyphens; labels 1-63 chars; cannot start/end with hyphen)." >&2
    exit 1
  fi

  log " - Setting hostname via hostnamectl to '$NEW_HOSTNAME'"
  hostnamectl set-hostname "$NEW_HOSTNAME" || { echo "ERROR: failed to set hostname" >&2; exit 1; }

  # Update /etc/hosts mapping on the 127.0.1.1 line (Ubuntu/Debian convention)
  short_name="${NEW_HOSTNAME%%.*}"
  hosts_line="127.0.1.1 ${NEW_HOSTNAME}"
  if [ "$short_name" != "$NEW_HOSTNAME" ]; then
    hosts_line="${hosts_line} ${short_name}"
  fi

  if grep -qE '^127\.0\.1\.1\b' /etc/hosts; then
    sed -i -E "s/^127\\.0\\.1\\.1\s+.*/${hosts_line//\//\/}/" /etc/hosts
  else
    printf '%s\n' "$hosts_line" >> /etc/hosts
  fi

  log " - Hostname set. New /etc/hosts entry: $(grep -E '^127\.0\.1\.1\b' /etc/hosts || true)"
fi


log "15) Install jetson-stats (jtop) and patch version mapping"
apt-get install -y python3-pip
pip3 install -U jetson-stats
systemctl daemon-reload || true
systemctl restart jtop.service || true

# Patch jetson-stats to map L4T 36.4.4 -> JetPack 6.2.1
JTOP_VARS_FILE=$(python3 - <<'PY'
import os
try:
    import jtop.core.jetson_variables as v
    print(os.path.abspath(v.__file__))
except Exception:
    pass
PY
)
if [ -z "$JTOP_VARS_FILE" ]; then
  JTOP_VARS_FILE="/usr/local/lib/python3.10/dist-packages/jtop/core/jetson_variables.py"
fi
if [ -f "$JTOP_VARS_FILE" ]; then
  if ! grep -q '"36.4.4": "6.2.1",' "$JTOP_VARS_FILE"; then
    sed -i -E '0,/"36\.4\.3": "6\.2",/s//"36.4.4": "6.2.1",\n    "36.4.3": "6.2",/' "$JTOP_VARS_FILE" || true
  fi
fi
systemctl restart jtop.service || true

log "16) Ensure swapfile size is $SWAP_SIZE (default 8G)"
to_bytes() {
  local s="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --from=iec "$s" 2>/dev/null && return 0
  fi
  case "$s" in
    *[Gg]*) echo $(( ${s%[Gg]*} * 1073741824 ));;
    *[Mm]*) echo $(( ${s%[Mm]*} * 1048576 ));;
    *[Kk]*) echo $(( ${s%[Kk]*} * 1024 ));;
    *) echo "$s";;
  esac
}
DESIRED_BYTES=$(to_bytes "$SWAP_SIZE")
if [ -z "$DESIRED_BYTES" ] || [ "$DESIRED_BYTES" -le 0 ]; then
  DESIRED_BYTES=$((8*1024*1024*1024))
fi

CURRENT_BYTES=0
[ -f /swapfile ] && CURRENT_BYTES=$(stat -c %s /swapfile 2>/dev/null || echo 0)

if [ "$CURRENT_BYTES" -eq "$DESIRED_BYTES" ]; then
  log " - Existing /swapfile already $SWAP_SIZE; leaving as-is."
else
  log " - (Re)creating /swapfile to $SWAP_SIZE"
  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile
  if fallocate -l "$DESIRED_BYTES" /swapfile 2>/dev/null; then
    :
  else
    dd if=/dev/zero of=/swapfile bs=1M count=$((DESIRED_BYTES/1048576)) status=none || true
  fi
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  if grep -qE '^/swapfile\b' /etc/fstab; then
    sed -i -E 's#^/swapfile\s+.*#/swapfile none swap sw 0 0#' /etc/fstab
  else
    printf '%s\n' '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
fi

if [ "$REBOOT" -eq 1 ]; then
  log "Final: rebooting now to apply Xorg changes…"
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested."
  echo "Xorg drop-ins take effect after a restart of the display server; a full reboot is simplest."
  echo "Reboot later with: sudo systemctl reboot"
fi
