#!/usr/bin/env bash

set -euo pipefail

REBOOT=${REBOOT:-0}
for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --vnc-backend=*) VNC_BACKEND="${arg#*=}" ;;
    --vnc-no-encryption|--vnc-insecure) VNC_NO_ENCRYPTION=1 ; VNC_ENCRYPTION_EXPLICIT=1 ;;
    --vnc-password=*|--vnc-pass=*) VNC_PASSWORD="${arg#*=}" ;;
    --hostname=*|--set-hostname=*) NEW_HOSTNAME="${arg#*=}" ;;
    --swap-size=*) SWAP_SIZE="${arg#*=}" ;;
    --mks) MICROK8S=1 ;;
    --k3s) K3S=1 ;;
    --help|-h) echo "Usage: $0 [--reboot] [--mks] [--k3s] [--vnc-backend=grd|x11vnc] [--vnc-password=PASS] [--vnc-no-encryption] [--hostname=NAME] [--swap-size=SIZE] [SSH_KEY_PATH=...]" ; exit 0 ;;
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }
VNC_BACKEND=${VNC_BACKEND:-grd}
VNC_NO_ENCRYPTION=${VNC_NO_ENCRYPTION:-0}
SWAP_SIZE=${SWAP_SIZE:-8G}
MICROK8S=${MICROK8S:-0}
K3S=${K3S:-0}

VNC_ENCRYPTION_EXPLICIT=${VNC_ENCRYPTION_EXPLICIT:-0}
# Only adjust VNC encryption defaults when a password is supplied on this run.
# When the script runs without --vnc-password, leave all existing VNC settings untouched.
if [ -n "${VNC_PASSWORD:-}" ] && [ "${VNC_BACKEND}" = "grd" ] && [ "${VNC_ENCRYPTION_EXPLICIT}" -eq 0 ]; then
  VNC_NO_ENCRYPTION=1
fi

resolve_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  if logname >/dev/null 2>&1; then ln=$(logname 2>/dev/null || true); [ -n "$ln" ] && [ "$ln" != "root" ] && { printf '%s' "$ln"; return; }; fi
  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}
USERNAME="$(resolve_user)"
[ -n "$USERNAME" ] || { echo "ERROR: could not resolve a non-root user." >&2; exit 1; }
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"

# 0) Configure German keyboard layout (system-wide + GNOME + GDM)
log "0) Set German keyboard layout (system + GNOME + GDM)"
# Console + X11 defaults
localectl set-keymap de 2>/dev/null || true
localectl set-x11-keymap de 2>/dev/null || true
# Ensure /etc/default/keyboard reflects 'de' (helps TTYs and early boot)
if [ -f /etc/default/keyboard ]; then
  sed -i -E 's/^XKBLAYOUT=.*/XKBLAYOUT="de"/' /etc/default/keyboard || true
else
  cat >/etc/default/keyboard <<'EOF'
XKBMODEL="pc105"
XKBLAYOUT="de"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
EOF
fi
# Apply to current console if possible (best-effort)
udevadm trigger --subsystem-match=input --action=change 2>/dev/null || true
command -v setupcon >/dev/null 2>&1 && setupcon -k 2>/dev/null || true
# Set GNOME defaults for user sessions (system dconf) and GDM greeter
install -d -m 0755 /etc/dconf/db/local.d
cat >/etc/dconf/db/local.d/00-keyboard-de <<'EOF'
[org/gnome/desktop/input-sources]
sources=[('xkb','de')]
xkb-options=['terminate:ctrl_alt_bksp']
EOF
install -d -m 0755 /etc/dconf/db/gdm.d
cat >/etc/dconf/db/gdm.d/00-keyboard-de <<'EOF'
[org/gnome/desktop/input-sources]
sources=[('xkb','de')]
xkb-options=['terminate:ctrl_alt_bksp']
EOF
dconf update 2>/dev/null || true

log "1) Install OpenSSH + dconf tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server dconf-cli nano btop curl git-lfs
git lfs install --system || true
systemctl enable --now ssh || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow OpenSSH || true; fi

# 1.1) Install NVIDIA JetPack SDK meta-package
log "1.1) Install NVIDIA JetPack SDK (nvidia-jetpack)"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-jetpack

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

log "12) Create default UNENCRYPTED GNOME keyring (no UI prompts)"
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


if [ -n "${VNC_PASSWORD:-}" ]; then
  log "13) VNC / Remote Desktop server setup (backend: ${VNC_BACKEND})"
  USER_UID=$(id -u "$USERNAME")
  USER_ENV=("XDG_RUNTIME_DIR=/run/user/${USER_UID}" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${USER_UID}/bus")
  USER_BUS="/run/user/${USER_UID}/bus"
  TIMEOUT="timeout 10s"

  if [ "${VNC_BACKEND}" = "grd" ]; then
    # --- GNOME Remote Desktop (VNC) ---
    apt-get install -y gnome-remote-desktop libsecret-tools || true
    # Ensure Wayland is enabled in GDM for GNOME Remote Desktop (VNC) to function correctly
    GDM_CONF="/etc/gdm3/custom.conf"
    if [ -f "$GDM_CONF" ]; then
      if grep -qE '^[#[:space:]]*WaylandEnable[[:space:]]*=' "$GDM_CONF"; then
        sed -i -E 's/^[#[:space:]]*WaylandEnable[[:space:]]*=.*/WaylandEnable=true/' "$GDM_CONF" || true
      else
        # Make sure the [daemon] section exists and append the setting
        grep -q '^\[daemon\]' "$GDM_CONF" || printf '\n[daemon]\n' >> "$GDM_CONF"
        printf 'WaylandEnable=true\n' >> "$GDM_CONF"
      fi
      log " - Enabled Wayland in GDM (WaylandEnable=true) for GNOME Remote Desktop VNC. Log out/in (or reboot) to apply."
    fi
    # VNC protocol uses only the first 8 **bytes** (DES). Force ASCII and 8 bytes for broad client compatibility (e.g., RealVNC).
    VNC_PASS8="$(printf '%s' "$VNC_PASSWORD" | LC_ALL=C tr -cd '[:print:]' | cut -b 1-8)"
    if [ -z "$VNC_PASS8" ]; then
      log " - WARNING: Provided VNC password had no ASCII bytes; falling back to first 8 characters."
      VNC_PASS8="${VNC_PASSWORD:0:8}"
    fi

    DEFER_GRD=0

    # If there is no user D-Bus session yet OR the user session bus is not responding OR
    # gnome-remote-desktop is not active, defer setup to the next GUI login to avoid blocking here.
    if [ ! -S "$USER_BUS" ] || \
       ! sudo -u "$USERNAME" env "${USER_ENV[@]}" gdbus call --session \
          --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
          --method org.freedesktop.DBus.ListNames >/dev/null 2>&1 || \
       ! sudo -u "$USERNAME" systemctl --user is-active --quiet gnome-remote-desktop.service; then
      log " - No ready user D-Bus/GRD session; deferring GNOME Remote Desktop setup to first GUI login."
      # Persist the password for the helper
      sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.config" || true
      sudo -u "$USERNAME" bash -lc 'umask 177; printf "%s\n" '""$VNC_PASS8""' > "$HOME/.config/gnome-remote-desktop.vncpass"'

      DEFER_GRD=1

      # Create an autostart helper that seeds the password and restarts g-r-d on login
      sudo -u "$USERNAME" install -d -m 0755 "$HOME_DIR/.local/bin" "$HOME_DIR/.config/autostart"
      sudo -u "$USERNAME" tee "$HOME_DIR/.local/bin/grd-ensure-vnc-pass.sh" >/dev/null <<'EOSH'
#!/bin/sh
set -e
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
PASS_FILE="$HOME/.config/gnome-remote-desktop.vncpass"
[ -s "$PASS_FILE" ] || exit 0
PASS=$(head -n1 "$PASS_FILE")
[ -n "$PASS" ] || exit 0
# Store secret then configure
printf "%s" "$PASS" | secret-tool store --label "GNOME Remote Desktop VNC password" xdg:schema org.gnome.RemoteDesktop.VncPassword || true
grdctl vnc set-auth-method password || true
grdctl vnc disable-view-only || true
grdctl vnc enable || true
gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true
if grdctl --help 2>&1 | grep -q -- '--headless'; then printf "%s" "$PASS" | grdctl --headless vnc set-password || true; else grdctl vnc set-password "$PASS" || true; fi
systemctl --user enable --now gnome-remote-desktop.service || true
systemctl --user enable --now gnome-remote-desktop-headless.service 2>/dev/null || true
EOSH
      sudo -u "$USERNAME" chmod 700 "$HOME_DIR/.local/bin/grd-ensure-vnc-pass.sh"

      sudo -u "$USERNAME" tee "$HOME_DIR/.config/autostart/grd-ensure-vnc-pass.desktop" >/dev/null <<'EODSK'
[Desktop Entry]
Type=Application
Name=Ensure VNC password (GNOME Remote Desktop)
Exec=/bin/sh -lc "$HOME/.local/bin/grd-ensure-vnc-pass.sh"
X-GNOME-Autostart-enabled=true
EODSK
      # Also drop through to create the systemd user override and helper service below; they will activate on login
    fi

    if [ "$DEFER_GRD" -eq 0 ]; then
    if command -v grdctl >/dev/null 2>&1; then
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc enable || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc set-auth-method password || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc disable-view-only || true
      # Set VNC password: GNOME 42 (Jammy) expects an argument; newer versions accept stdin with --headless
      if sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl --help 2>&1 | grep -q -- '--headless'; then
        # Newer grdctl
        printf '%s' "$VNC_PASS8" | $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl --headless vnc set-password || true
      else
        # Jammy GNOME 42 path: pass the password as an argument
        $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl vnc set-password "$VNC_PASS8" || true
      fi
      printf '%s' "$VNC_PASS8" | $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" secret-tool store --label="GNOME Remote Desktop VNC password" xdg:schema org.gnome.RemoteDesktop.VncPassword || true
      if [ "${VNC_NO_ENCRYPTION}" -eq 1 ]; then
        $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true
      fi
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop.service || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop-headless.service 2>/dev/null || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" grdctl status || true
    else
      # Fallback to gsettings + secret-tool
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc auth-method 'password' || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc view-only false || true
      if [ "${VNC_NO_ENCRYPTION}" -eq 1 ]; then
        $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true
      fi
      printf '%s' "$VNC_PASS8" | $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" secret-tool store --label="GNOME Remote Desktop VNC password" xdg:schema org.gnome.RemoteDesktop.VncPassword || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop.service || true
      $TIMEOUT sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user enable --now gnome-remote-desktop-headless.service 2>/dev/null || true
    fi

    fi

    # Ensure gnome-remote-desktop starts after the keyring is available (prevents password reset on boot)
    sudo -u "$USERNAME" install -d -m 0755 "$HOME_DIR/.config/systemd/user/gnome-remote-desktop.service.d"
    sudo -u "$USERNAME" tee "$HOME_DIR/.config/systemd/user/gnome-remote-desktop.service.d/override.conf" >/dev/null <<'EOC'
[Unit]
After=gnome-keyring-daemon.service graphical-session.target
Wants=gnome-keyring-daemon.service
EOC
    $TIMEOUT sudo -u "$USERNAME" systemctl --user daemon-reload || true
    $TIMEOUT sudo -u "$USERNAME" systemctl --user enable --now gnome-remote-desktop.service || true

    # Create a user service to (re)seed the VNC password after session & keyring are up
    sudo -u "$USERNAME" install -d -m 0755 "$HOME_DIR/.config/systemd/user"
    sudo -u "$USERNAME" tee "$HOME_DIR/.config/systemd/user/grd-ensure-vnc-pass.service" >/dev/null <<'EOUNIT'
[Unit]
Description=Ensure GNOME Remote Desktop VNC password is set
After=gnome-keyring-daemon.service graphical-session.target
Wants=gnome-keyring-daemon.service

[Service]
Type=oneshot
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
Environment=XDG_RUNTIME_DIR=%t
ExecStart=/bin/sh -lc '
  PASS_FILE="$HOME/.config/gnome-remote-desktop.vncpass";
  [ -f "$PASS_FILE" ] || exit 0;
  PASS=$(head -n1 "$PASS_FILE");
  [ -n "$PASS" ] || exit 0;

  grdctl vnc set-auth-method password || true;
  grdctl vnc disable-view-only || true;
  grdctl vnc enable || true;
  # Disable VNC encryption for broad client compatibility (e.g., RealVNC)
  gsettings set org.gnome.desktop.remote-desktop.vnc encryption "['none']" || true;

  if grdctl --help 2>&1 | grep -q -- '--headless'; then printf "%s" "$PASS" | grdctl --headless vnc set-password || grdctl --headless vnc set-password "$PASS" || true; else grdctl vnc set-password "$PASS" || true; fi;

  systemctl --user enable --now gnome-remote-desktop.service || true;
  systemctl --user enable --now gnome-remote-desktop-headless.service 2>/dev/null || true;
'

[Install]
WantedBy=default.target
EOUNIT
    $TIMEOUT sudo -u "$USERNAME" systemctl --user daemon-reload || true

    # Persist the chosen password to the user's config for the ensure service (permissions 600)
    sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.config"
    sudo -u "$USERNAME" bash -lc 'umask 177; printf "%s\n" "'"$VNC_PASS8"'" > "$HOME/.config/gnome-remote-desktop.vncpass"'

    # Enable the ensure service to run at each login
    $TIMEOUT sudo -u "$USERNAME" systemctl --user enable --now grd-ensure-vnc-pass.service || true

    # If linger was enabled earlier, it can start the service too early (before keyring). Disable it to avoid random password regeneration.
    if loginctl show-user "$USERNAME" -p Linger 2>/dev/null | grep -q '=yes'; then
      loginctl disable-linger "$USERNAME" || true
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
  log "13) VNC: no changes (run with --vnc-password=... to modify VNC settings)"
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

log "15) Disable zram (nvzramconfig)"
if systemctl is-enabled nvzramconfig >/dev/null 2>&1; then
  systemctl disable nvzramconfig || true
  systemctl stop nvzramconfig || true
  log " - zram (nvzramconfig) disabled."
else
  log " - zram already disabled; skipping."
fi


log "16) Install jetson-stats (jtop) and patch version mapping"
if ! python3 -c "import jtop" >/dev/null 2>&1; then
  apt-get install -y python3-pip
  pip3 install -U jetson-stats
  systemctl daemon-reload || true
  systemctl restart jtop.service || true
fi

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

log "17) Ensure swapfile size is $SWAP_SIZE (default 8G)"
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

log "18) Repair Git & Git LFS permissions for all repos under $HOME_DIR"
# Ensure user's global LFS hooks/config are installed (per-user), independent of repo
if command -v git >/dev/null 2>&1; then
  sudo -u "$USERNAME" git lfs install --skip-repo >/dev/null 2>&1 || true

  # Iterate over all .git directories in the user's home and fix permissions for .git and .git/lfs
  while IFS= read -r -d '' gitdir; do
    repo="${gitdir%/.git}"

    # Fix ownership of the Git metadata to the actual user
    chown -R "$USERNAME":"$USERNAME" "$gitdir" 2>/dev/null || true

    # Fix LFS cache/objects/locks directories if present
    if [ -d "$gitdir/lfs" ]; then
      chown -R "$USERNAME":"$USERNAME" "$gitdir/lfs" 2>/dev/null || true
      find "$gitdir/lfs" -type d -exec chmod u+rwx,go-rwx {} + 2>/dev/null || true
      find "$gitdir/lfs" -type f -exec chmod u+rw,go-rwx {} + 2>/dev/null || true
    fi

    # Mark repository as safe for the user to avoid "dubious ownership" issues if history of root edits exists
    if ! sudo -u "$USERNAME" git config --global --get-all safe.directory | grep -Fxq "$repo" 2>/dev/null; then
      sudo -u "$USERNAME" git config --global --add safe.directory "$repo" || true
    fi
  done < <(find "$HOME_DIR" -type d -name .git -prune -print0 2>/dev/null)
fi

log "19) Set Jetson power mode to MAXN (nvpmodel)"
if command -v nvpmodel >/dev/null 2>&1; then
  if timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
    log " - Power mode already MAXN; skipping."
  else
    for id in 0 1 2 3 4 5 6 7 8 9; do
      if timeout 5s nvpmodel -m "$id" >/dev/null 2>&1; then
        sleep 1
        if timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
          log " - Set power mode to MAXN via nvpmodel -m $id"
          break
        fi
      fi
    done
    if ! timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
      log " - WARNING: Could not set MAXN automatically. Available modes:"
      timeout 5s nvpmodel -q 2>/dev/null || true
      log "   You may need to check /etc/nvpmodel.conf for mode numbers."
    fi
  fi
else
  log " - nvpmodel not found; skipping."
fi

log "20) Install Docker Engine and plugins (if missing)"
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  log " - Docker already installed; ensuring plugins present"
  apt-get install -y docker-buildx-plugin docker-compose-plugin || true
fi

log "21) Configure Docker default runtime to NVIDIA"
DAEMON_JSON=/etc/docker/daemon.json
DOCKER_NVIDIA_JSON='{
  "runtimes": {
    "nvidia": {
      "path": "nvidia-container-runtime",
      "runtimeArgs": []
    }
  },
  "default-runtime": "nvidia"
}'
if [ -f "$DAEMON_JSON" ]; then
  if ! cmp -s <(echo "$DOCKER_NVIDIA_JSON") "$DAEMON_JSON"; then
  cp "$DAEMON_JSON" "$DAEMON_JSON.bak.$(date +%s)" || true
  echo "$DOCKER_NVIDIA_JSON" > "$DAEMON_JSON"
  systemctl daemon-reload || true
  systemctl restart docker || true
  else
  log " - Docker daemon.json already matches NVIDIA runtime config; skipping replace."
  fi
fi

log "22) Ensure $USERNAME is in 'docker' group"
if ! getent group docker >/dev/null; then
  groupadd docker || true
fi
if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx docker; then
  log " - $USERNAME already in docker group; skipping."
else
  usermod -aG docker "$USERNAME" || true
  log " - Added $USERNAME to docker group. You may need to log out/in for group changes to take effect."
fi


log "23) Force snapd 2.68.5 (rev 24724) and hold (always)"
snap download snapd --revision=24724
snap ack snapd_24724.assert
snap install snapd_24724.snap
snap refresh --hold snapd
rm -f snapd_24724.assert snapd_24724.snap || true

log "24) Remove preinstalled games (apt & snap)"

# APT packages commonly pulled in by Ubuntu/Jetson images
# (GNOME games, see: aisleriot, gnome-mines, gnome-mahjongg, gnome-sudoku, gnome-chess,
#  gnome-robots, gnome-klotski, gnome-taquin, tali, four-in-a-row, hitori, gnome-nibbles,
#  and the meta packages gnome-games and gnome-games-app)
APT_GAMES=(
  gnome-games
  gnome-games-app
  aisleriot
  gnome-mines
  gnome-mahjongg
  gnome-sudoku
  gnome-chess
  gnome-robots
  gnome-klotski
  gnome-taquin
  tali
  four-in-a-row
  hitori
  gnome-nibbles
  cheese
)

TO_PURGE=()
for p in "${APT_GAMES[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 && TO_PURGE+=("$p") || true
done

if [ ${#TO_PURGE[@]} -gt 0 ]; then
  log " - Purging APT games: ${TO_PURGE[*]}"
  apt-get purge -y "${TO_PURGE[@]}" || true
  apt-get autoremove -y || true
else
  log " - No listed APT games installed; skipping purge"
fi

# Remove snap-installed GNOME games if present
if command -v snap >/dev/null 2>&1; then
  SNAP_GAMES=(
    gnome-2048
    gnome-chess
    gnome-mines
    gnome-sudoku
    gnome-mahjongg
    gnome-nibbles
    gnome-klotski
    gnome-taquin
    tali
  )
  for s in "${SNAP_GAMES[@]}"; do
    if snap list "$s" >/dev/null 2>&1; then
      log " - Removing snap: $s"
      snap remove --purge "$s" || true
    fi
  done
else
  log " - snap not installed; skipping snap game removal"
fi


log "25) Install MicroK8s (snap) [optional]"
if [ "${MICROK8S}" -eq 1 ]; then
  if command -v snap >/dev/null 2>&1; then
    if snap list microk8s >/dev/null 2>&1; then
      log " - MicroK8s already installed; skipping."
    else
      log " - Installing MicroK8s (snap)"
      snap install microk8s --classic || log " - ERROR: snap install microk8s failed"
    fi
    # Ensure the user can run microk8s without sudo
    if ! getent group microk8s >/dev/null; then
      groupadd microk8s || true
    fi
    if ! id -nG "$USERNAME" | tr ' ' '\n' | grep -qx microk8s; then
      usermod -aG microk8s "$USERNAME" || true
      log " - Added $USERNAME to 'microk8s' group (log out/in to take effect)."
    fi
    # Prepare kube config directory for the user (non-blocking convenience)
    sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.kube" || true
    chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.kube" || true

    # Provide a kubectl alias for interactive shells
    ALIAS_LINE="alias kubectl='microk8s kubectl'"
    # System-wide profile script (affects interactive shells)
    echo "$ALIAS_LINE" > /etc/profile.d/microk8s-kubectl.sh
    chmod 644 /etc/profile.d/microk8s-kubectl.sh
    # Ensure the resolved user's .bashrc also has the alias (idempotent)
    if ! grep -qxF "$ALIAS_LINE" "$HOME_DIR/.bashrc" 2>/dev/null; then
      echo "$ALIAS_LINE" >> "$HOME_DIR/.bashrc"
    fi
    chown "$USERNAME":"$USERNAME" "$HOME_DIR/.bashrc" || true

    # Wait for MicroK8s to become ready (up to 5 minutes) to avoid blocking indefinitely
    if command -v microk8s >/dev/null 2>&1; then
      timeout 300s microk8s status --wait-ready || log " - WARNING: MicroK8s not ready within 5 minutes"
    fi
  else
    log " - snap not available; skipping MicroK8s install"
  fi
else
  log " - Skipping MicroK8s install (use --mks to enable)"
fi

# --- Step 26: Clone jetson-containers and run install.sh (only if missing) ---
log "26) Clone jetson-containers and run install.sh (only if missing)"
# Ensure git is available
if ! command -v git >/dev/null 2>&1; then
  apt-get install -y git
fi

TARGET_DIR="$HOME_DIR/git/jetson-containers"
install -d -m 0755 "$HOME_DIR/git"
if [ -d "$TARGET_DIR" ]; then
  log " - $TARGET_DIR already exists; skipping clone and install.sh"
else
  log " - Cloning jetson-containers"
  sudo -u "$USERNAME" git clone https://github.com/robertZaufall/jetson-containers "$TARGET_DIR" || true
  # Run install.sh if present after clone
  if [ -x "$TARGET_DIR/install.sh" ]; then
    sudo -u "$USERNAME" bash -lc "cd '$TARGET_DIR' && ./install.sh" || true
  else
    log " - WARNING: install.sh not found or not executable at $TARGET_DIR after clone"
  fi
fi

# --- Step 27: Install K3s [optional] ---
log "27) Install K3s [optional]"
if [ "${K3S}" -eq 1 ]; then
  # Disable IPv6 at runtime (as requested)
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1 || true

  # --- K3s host prerequisites: kernel modules & sysctls ---
  # Load required modules and persist at boot
  cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
  modprobe overlay || true
  modprobe br_netfilter || true

  # Ensure Kubernetes networking sysctls (iptables must see bridged traffic; ip_forward required)
  cat >/etc/sysctl.d/99-kubernetes.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
  sysctl --system || true

  # Switch iptables to legacy if the system is using nft and k3s/docker have trouble (recommended by k3s docs)
  if command -v update-alternatives >/dev/null 2>&1; then
    if update-alternatives --query iptables 2>/dev/null | grep -q 'Value: /usr/sbin/iptables-nft'; then
      update-alternatives --set iptables /usr/sbin/iptables-legacy || true
    fi
    if update-alternatives --query ip6tables 2>/dev/null | grep -q 'Value: /usr/sbin/ip6tables-nft'; then
      update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy || true
    fi
  fi

  # Ensure Docker is up before starting k3s --docker
  systemctl enable --now docker || true
  timeout 60s bash -lc 'until docker info >/dev/null 2>&1; do sleep 2; done' || log " - WARNING: Docker not responding at /var/run/docker.sock"

  # Wait for IPv4 default route; k3s fails with "no default routes found" if none
  if ! ip route show default | grep -q '^default'; then
    log " - Waiting up to 90s for default IPv4 route..."
    timeout 90s bash -lc 'until ip route show default | grep -q "^default"; do sleep 2; done' || log " - WARNING: no default route after waiting; consider static gateway or --node-ip/--advertise-address"
  fi

  # Derive NODE_IP from the primary route if available
  NODE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}')

  # Ensure kube config directory for the resolved user
  sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.kube" || true
  chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.kube" || true

  # Install K3s using Docker and write kubeconfig to user's home, passing --node-ip/--advertise-address if available
  K3S_INSTALL_ARGS="server --docker --write-kubeconfig-mode 644 --write-kubeconfig '$HOME_DIR/.kube/config'"
  if [ -n "$NODE_IP" ]; then
    K3S_INSTALL_ARGS="$K3S_INSTALL_ARGS --node-ip $NODE_IP --advertise-address $NODE_IP"
  fi
  sh -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=\"$K3S_INSTALL_ARGS\" sh -s -" || true

  # Ensure k3s waits for network-online and Docker at boot
  install -d -m 0755 /etc/systemd/system/k3s.service.d
  cat >/etc/systemd/system/k3s.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target docker.service
Wants=network-online.target docker.service
EOF
  systemctl daemon-reload
  systemctl restart k3s || true

  # Give k3s a brief moment to start and collect diagnostics if it fails
  sleep 3
  systemctl is-active --quiet k3s || journalctl -u k3s -n 100 --no-pager || true

  # Post-install checks (non-blocking with timeouts)
  systemctl status k3s --no-pager || true
  timeout 120s kubectl cluster-info || true
  kubectl get nodes || true
else
  log " - Skipping K3s install (use --k3s to enable)"
fi

# --- Step 28: Install Helm (Kubernetes package manager) [optional, only if K3s is installed] ---
if [ "${K3S}" -eq 1 ]; then
  log "28) Install Helm (Kubernetes package manager)"
  if command -v helm >/dev/null 2>&1; then
    log " - Helm already installed; skipping."
  else
    # Add official Helm apt repository and key (per helm.sh docs)
    apt-get install -y apt-transport-https gnupg curl || true
    curl -fsSL https://baltocdn.com/helm/signing.asc | gpg --dearmor | tee /usr/share/keyrings/helm.gpg >/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" \
      > /etc/apt/sources.list.d/helm-stable-debian.list
    apt-get update -y
    apt-get install -y helm
  fi
fi

# --- Step 29: Install guvcview ---
log "29) Install guvcview"
apt-get install -y guvcview


# --- Step 30: Clean some system components ---
# log "30) Clean some system components"
# APT_PURGE=(
#   gnome-software
#   packagekit
#   packagekit-tools
#   update-notifier
#   tracker3
#   tracker3-miners
#   gnome-online-accounts
#   fwupd
# )
# log "Stopping services (best effort)…"
# systemctl stop packagekit 2>/dev/null || true
# systemctl stop fwupd 2>/dev/null || true
# TRACKER_CACHE="${HOME}/.cache/tracker3"
# if [ -d "$TRACKER_CACHE" ]; then
#   log "Removing user Tracker cache at $TRACKER_CACHE"
#   rm -rf "$TRACKER_CACHE" || true
# fi
# log "Purging desktop background-updaters & indexers…"
# TO_PURGE=()
# for p in "${APT_PURGE[@]}"; do
#   dpkg -s "$p" >/dev/null 2>&1 && TO_PURGE+=("$p")
# done
# if [ "${#TO_PURGE[@]}" -gt 0 ]; then
#   apt-get update -y
#   DEBIAN_FRONTEND=noninteractive apt-get purge -y "${TO_PURGE[@]}"
# else
#   log "Nothing from main list is installed; skipping."
# fi
# log "Autoremove any orphaned deps…"
# DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
# apt-get clean
# log "Masking leftover services if any…"
# systemctl mask packagekit.service 2>/dev/null || true
# systemctl mask fwupd.service 2>/dev/null || true


if [ "$REBOOT" -eq 1 ]; then
  log "Final: rebooting now to apply Xorg changes…"
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested."
  echo "Xorg drop-ins take effect after a restart of the display server; a full reboot is simplest."
  echo "Reboot later with: sudo systemctl reboot"
fi
