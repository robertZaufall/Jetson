#!/usr/bin/env bash

set -euo pipefail
log(){ printf '\n=== %s ===\n' "$*"; }

resolve_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  if logname >/dev/null 2>&1; then ln=$(logname 2>/dev/null || true); [ -n "$ln" ] && [ "$ln" != "root" ] && { printf '%s' "$ln"; return; }; fi
  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}
USERNAME="$(resolve_user)"
[ -n "$USERNAME" ] || { echo "ERROR: could not resolve a non-root user." >&2; exit 1; }
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"

log "1) GNOME system-wide: disable idle/lock/suspend (dconf)"
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
lock-delay=uint32 0
ubuntu-lock-on-suspend=false

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='nothing'
sleep-inactive-ac-timeout=0
sleep-inactive-battery-type='nothing'
sleep-inactive-battery-timeout=0
idle-dim=false

[org/gnome/desktop/lockdown]
disable-lock-screen=true
EOF
install -d -m 0755 /etc/dconf/db/local.d/locks
cat >/etc/dconf/db/local.d/locks/00-nosleep-locks <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/ubuntu-lock-on-suspend
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/gnome/settings-daemon/plugins/power/idle-dim
/org/gnome/desktop/lockdown/disable-lock-screen
EOF
dconf update || true

log "2) GDM greeter: prevent idle/suspend"
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

[org/gnome/desktop/lockdown]
disable-lock-screen=true

[org/gnome/desktop/screensaver]
lock-enabled=false
idle-activation-enabled=false
lock-delay=uint32 0
ubuntu-lock-on-suspend=false
EOF
dconf update || true

log "3) X11 PERMANENT: disable DPMS & blanking at the Xorg level"
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

log "4) X11 PERMANENT: user-session fallback to enforce no-blank via xset"
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

# Wayland/Xorg: inhibit idle/lock at the session level as a belt-and-suspenders fix (GNOME 46+)
cat >/usr/local/bin/gnome-inhibit-idle <<'EOF'
#!/bin/sh
# Require GNOME session
if [ "${XDG_CURRENT_DESKTOP#*GNOME}" != "$XDG_CURRENT_DESKTOP" ] || [ "$XDG_CURRENT_DESKTOP" = "GNOME" ]; then
  exec gnome-session-inhibit \
    --inhibit logout \
    --inhibit switch-user \
    --inhibit suspend \
    --inhibit idle \
    --reason "Prevent idle/lock" \
    sleep infinity
fi
exit 0
EOF
chmod +x /usr/local/bin/gnome-inhibit-idle
cat >/etc/xdg/autostart/90-gnome-inhibit-idle.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Prevent screen lock/idle
Exec=/usr/local/bin/gnome-inhibit-idle
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=true
EOF

# Also ensure user-level settings at login in case profiles aren’t applied yet
cat >/usr/local/bin/gnome-ensure-no-lock <<'EOF'
#!/bin/sh
set -e
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
gsettings set org.gnome.desktop.session idle-delay 0 || true
gsettings set org.gnome.desktop.screensaver lock-enabled false || true
gsettings set org.gnome.desktop.screensaver idle-activation-enabled false || true
gsettings set org.gnome.desktop.screensaver lock-delay 0 || true
gsettings set org.gnome.desktop.screensaver ubuntu-lock-on-suspend false || true
gsettings set org.gnome.desktop.lockdown disable-lock-screen true || true
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing' || true
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0 || true
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 'nothing' || true
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0 || true
gsettings set org.gnome.settings-daemon.plugins.power idle-dim false || true
exit 0
EOF
chmod +x /usr/local/bin/gnome-ensure-no-lock
cat >/etc/xdg/autostart/91-gnome-ensure-no-lock.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=Ensure no lock settings
Exec=/usr/local/bin/gnome-ensure-no-lock
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=true
EOF

log "5) Block suspend/hibernate at systemd level"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target || true

log "6) systemd-logind: ignore lid/suspend keys"
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

log "7) Disable TTY (virtual console) blanking"
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

log "8) Disable Wi-Fi powersave (NetworkManager)"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
wifi.powersave=2
EOF
if systemctl is-active --quiet NetworkManager 2>/dev/null || systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
  systemctl restart NetworkManager || true
fi

log "1) Enable GDM auto-login for user: $USERNAME"
GDM_CONF="/etc/gdm3/custom.conf"
install -d -m 0755 /etc/gdm3
touch "$GDM_CONF"
grep -q '^\[daemon\]' "$GDM_CONF" || printf '\n[daemon]\n' >> "$GDM_CONF"
awk -v user="$USERNAME" '
BEGIN{in_d=0; se=0; su=0}
{
  if ($0 ~ /^\[daemon\]/){in_d=1; print; next}
  if (in_d && $0 ~ /^\[/){ if(!se) print "AutomaticLoginEnable=true"; if(!su) print "AutomaticLogin=" user; in_d=0 }
  if (in_d){
    if ($0 ~ /^[#[:space:]]*AutomaticLoginEnable[[:space:]]*=/){print "AutomaticLoginEnable=true"; se=1; next}
    if ($0 ~ /^[#[:space:]]*AutomaticLogin[[:space:]]*=/){print "AutomaticLogin=" user; su=1; next}
    # Intentionally leave any existing WaylandEnable= line unchanged to avoid breaking GNOME Remote Desktop VNC
  }
  print
}
END{ if(in_d){ if(!se) print "AutomaticLoginEnable=true"; if(!su) print "AutomaticLogin=" user } }
' "$GDM_CONF" > "$GDM_CONF.tmp" && mv "$GDM_CONF.tmp" "$GDM_CONF"

log "2) Create default UNENCRYPTED GNOME keyring (no UI prompts)"
KEYRINGS_DIR="$HOME_DIR/.local/share/keyrings"
mkdir -p "$KEYRINGS_DIR"

DEFAULT_POINTER_FILE="$KEYRINGS_DIR/default"
DEFAULT_RING_FILE="$KEYRINGS_DIR/Default_keyring.keyring"

if [ -f "$DEFAULT_POINTER_FILE" ] && [ -f "$DEFAULT_RING_FILE" ]; then
  log " - Existing default keyring detected; leaving keyring unchanged."
  # Still ensure ownership/permissions are sane
  chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.local" || true
  chmod 700 "$KEYRINGS_DIR" 2>/dev/null || true
  chmod 600 "$DEFAULT_RING_FILE" 2>/dev/null || true
else
  # Backup any existing keyrings once (timestamped)
  if ls -A "$KEYRINGS_DIR" >/dev/null 2>&1; then
    TS=$(date +%Y%m%d-%H%M%S)
    BACKUP_DIR="$HOME_DIR/.local/share/keyrings-backup-$TS"
    cp -a "$KEYRINGS_DIR" "$BACKUP_DIR" || true
    chown -R "$USERNAME":"$USERNAME" "$BACKUP_DIR" || true
  fi

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
fi

cat >/etc/issue.keyring-note <<'EOF'
NOTE: Keyring configured for **unsafe storage**. A plaintext keyring was created and set as default,
so GNOME will not prompt to set a keyring password. Secrets stored via libsecret/gnome-keyring are
unencrypted on disk. Change this policy if you need encryption.
EOF
