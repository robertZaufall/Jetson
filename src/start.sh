#!/usr/bin/env bash

# Execution outline:
# Preflight. Require root, parse flags, detect the target user/platform, and choose defaults.
# Runtime steps are numbered automatically by `step()` so this outline stays stable when steps move.
# - Configure keyboard, desktop no-idle policy, SSH, auto-login, keyring, and optional VNC.
# - Apply Jetson-specific platform setup: JetPack packages, jtop, swap, power mode, Docker/NVIDIA runtime.
# - Install optional Kubernetes tooling and developer tools.
# - Apply optional registry, hostname, SSH key, and Git identity settings.
# Final. Reboot if requested; otherwise print reboot guidance.

set -euo pipefail

REBOOT=${REBOOT:-0}
REG_IP=${REG_IP:-${REG:-}}
GIT_USER=${GIT_USER:-}
GIT_EMAIL=${GIT_EMAIL:-}
JETSON_USER=${JETSON_USER:-jetson}

usage() {
  echo "Usage: $0 [--user=NAME] [--reboot] [--mks] [--k3s] [--vnc-backend=x11vnc] [--vnc-password=PASS] [--hostname=NAME] [--swap-size=SIZE] [SSH_KEY_PATH=PATH|--ssh-key-path=PATH] [REG=REGISTRY_IP|--reg=REGISTRY_IP] [--git-user=NAME --git-email=EMAIL]"
}

for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --vnc-backend=*) VNC_BACKEND="${arg#*=}" ; VNC_BACKEND_SET=1 ;;
    --vnc-no-encryption|--vnc-insecure) : ;; # Accepted for compatibility; x11vnc does not use this setting.
    --vnc-password=*|--vnc-pass=*) VNC_PASSWORD="${arg#*=}" ;;
    --user=*|--username=*|--target-user=*) JETSON_USER="${arg#*=}" ;;
    --hostname=*|--set-hostname=*) NEW_HOSTNAME="${arg#*=}" ;;
    --swap-size=*) SWAP_SIZE="${arg#*=}" ;;
    SSH_KEY_PATH=*|--ssh-key-path=*) SSH_KEY_PATH="${arg#*=}" ;;
    --mks) MICROK8S=1 ;;
    --k3s) K3S=1 ;;
    --git-user=*) GIT_USER="${arg#*=}" ;;
    --git-email=*) GIT_EMAIL="${arg#*=}" ;;
    REG=*) REG_IP="${arg#*=}" ;;
    --reg=*) REG_IP="${arg#*=}" ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "Unknown option: $arg" >&2
      usage
      exit 1
      ;;
  esac
done

# Require root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: this script must be run as root (use sudo)." >&2
  exit 1
fi

log() {
  printf '\n=== %s ===\n' "$*"
}
STEP=0
step() {
  STEP=$((STEP + 1))
  log "$STEP) $*"
}

# Small helpers
apt_install_retry() {
  # Usage: apt_install_retry pkg1 [pkg2 ...]
  # Be resilient to transient DNS/network hiccups
  local missing_pkgs=() pkg status
  for pkg in "$@"; do
    status=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
    if ! printf '%s' "$status" | grep -q 'install ok installed'; then
      missing_pkgs+=("$pkg")
    fi
  done

  # Avoid `apt-get update` (and DNS lookups) when everything is already installed.
  if [ "${#missing_pkgs[@]}" -eq 0 ]; then
    return 0
  fi

  DEBIAN_FRONTEND=noninteractive apt-get update -y -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Acquire::Retries=3 "${missing_pkgs[@]}" || return 1
}

is_pkg_installed() {
  local pkg="$1" status
  status=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
  printf '%s' "$status" | grep -q 'install ok installed'
}

install_tailscale_repo() {
  local dist="$1" keyring_tmp list_tmp
  keyring_tmp=$(mktemp)
  list_tmp=$(mktemp)

  if ! curl -fsSL --retry 3 --connect-timeout 15 \
      "https://pkgs.tailscale.com/stable/ubuntu/${dist}.noarmor.gpg" -o "$keyring_tmp"; then
    rm -f "$keyring_tmp" "$list_tmp"
    return 1
  fi
  if ! install -m 0644 "$keyring_tmp" /usr/share/keyrings/tailscale-archive-keyring.gpg; then
    rm -f "$keyring_tmp" "$list_tmp"
    return 1
  fi

  if ! curl -fsSL --retry 3 --connect-timeout 15 \
      "https://pkgs.tailscale.com/stable/ubuntu/${dist}.tailscale-keyring.list" -o "$list_tmp"; then
    rm -f "$keyring_tmp" "$list_tmp"
    return 1
  fi
  if ! install -m 0644 "$list_tmp" /etc/apt/sources.list.d/tailscale.list; then
    rm -f "$keyring_tmp" "$list_tmp"
    return 1
  fi

  rm -f "$keyring_tmp" "$list_tmp"
  DEBIAN_FRONTEND=noninteractive apt-get update -y -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 || return 1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Acquire::Retries=3 tailscale || return 1
}

# Detect platform once. JetPack 7 covers both Thor and Orin, so hardware-specific
# behavior must key off the device model rather than the L4T major version.
detect_l4t() {
  local ver pkgver
  if pkgver=$(dpkg-query -W -f='${Version}' nvidia-l4t-core 2>/dev/null); then
    ver=$(printf '%s\n' "$pkgver" | sed -n 's/\b\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1)
  elif [ -r /etc/nv_tegra_release ]; then
    ver=$(sed -n "s/.*R\([0-9][0-9]*\) *\.* *REVISION *\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1.\2.\3/p" /etc/nv_tegra_release | head -n1)
  fi
  printf '%s' "${ver:-unknown}"
}

L4T_VERSION="$(detect_l4t)"
. /etc/os-release 2>/dev/null || true
UBUNTU_CODENAME=${UBUNTU_CODENAME:-${VERSION_CODENAME:-unknown}}
MODEL="$(tr -d '\0' </proc/device-tree/model 2>/dev/null || true)"
IS_THOR=0
echo "$MODEL" | grep -Eiq 'Thor' && IS_THOR=1
IS_ORIN_NX_OR_NANO=0
echo "$MODEL" | grep -Eiq 'Orin[[:space:]-]*(NX|Nano)' && IS_ORIN_NX_OR_NANO=1

VNC_BACKEND_SET=${VNC_BACKEND_SET:-0}
# Default to X11-only VNC (x11vnc). Wayland/GRD is intentionally not used for VNC.
if [ "${VNC_BACKEND_SET}" -eq 0 ]; then
  VNC_BACKEND="x11vnc"
fi
VNC_BACKEND=${VNC_BACKEND:-x11vnc}
# Auto-default swap size to 8G (8GB RAM) or 16G (16GB RAM) when not set
log "Platform: L4T ${L4T_VERSION:-unknown} on Ubuntu ${UBUNTU_CODENAME}; model: ${MODEL:-unknown}; VNC backend: ${VNC_BACKEND}"

if [ -z "${SWAP_SIZE:-}" ]; then
  mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$mem_kb" -ge $((12*1024*1024)) ]; then
    SWAP_SIZE=16G
  else
    SWAP_SIZE=8G
  fi
fi
MICROK8S=${MICROK8S:-0}
K3S=${K3S:-0}

USERNAME="$JETSON_USER"
USER_ENTRY=$(getent passwd "$USERNAME" || true)
[ -n "$USER_ENTRY" ] || { echo "ERROR: required user '$USERNAME' does not exist." >&2; exit 1; }
HOME_DIR=$(printf '%s\n' "$USER_ENTRY" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"

######################################################################################

# Configure German keyboard layout (system-wide + GNOME + GDM)
step "Set German keyboard layout (system + GNOME + GDM)"
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

######################################################################################

step "Install OpenSSH + dconf tools"
export DEBIAN_FRONTEND=noninteractive
# Use resilient installer to tolerate transient DNS/network issues.
if ! apt_install_retry openssh-server dconf-cli libglib2.0-bin nano btop curl git-lfs; then
  log " - WARNING: base tools not fully installed (offline?). Will continue."
  # Best-effort fallback without failing the whole script
  apt-get install -y openssh-server dconf-cli libglib2.0-bin nano btop curl git-lfs || true
fi
git lfs install --system || true
systemctl enable --now ssh || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ! ufw status 2>/dev/null | grep -qE '(^|[[:space:]])OpenSSH([[:space:]]|$)'; then
    ufw allow OpenSSH || true
  fi
fi

######################################################################################

# Install NVIDIA JetPack SDK meta-package
step "Install NVIDIA JetPack SDK (nvidia-jetpack)"
if ! apt_install_retry nvidia-jetpack; then
  log " - WARNING: could not install nvidia-jetpack now (repo/DNS?). Skipping."
fi

######################################################################################

step "Install Tailscale"
if is_pkg_installed tailscale; then
  log " - Tailscale already installed; ensuring tailscaled is enabled."
  systemctl enable --now tailscaled || true
else
  TAILSCALE_DIST="${UBUNTU_CODENAME:-noble}"
  case "$TAILSCALE_DIST" in
    jammy|noble) ;;
    *)
      log " - WARNING: unsupported Ubuntu codename '$TAILSCALE_DIST'; falling back to noble"
      TAILSCALE_DIST="noble"
      ;;
  esac

  if install_tailscale_repo "$TAILSCALE_DIST"; then
    systemctl enable --now tailscaled || true
  else
    log " - WARNING: could not install Tailscale now (repo/DNS?). Skipping."
  fi
fi

######################################################################################

step "GNOME system-wide: disable idle/lock/suspend (dconf)"
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

######################################################################################

step "GDM greeter: prevent idle/suspend"
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

######################################################################################

step "X11 permanent: disable DPMS & blanking at the Xorg level"
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

######################################################################################

step "X11 permanent: user-session fallback to enforce no-blank via xset"
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

######################################################################################

step "Block suspend/hibernate at systemd level"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target || true

######################################################################################

step "systemd-logind: ignore lid/suspend keys"
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

######################################################################################

step "Disable TTY (virtual console) blanking"
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

######################################################################################

step "Disable Wi-Fi powersave (NetworkManager)"
install -d -m 0755 /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/00-wifi-powersave-off.conf <<'EOF'
[connection]
wifi.powersave=2
EOF
if systemctl is-active --quiet NetworkManager 2>/dev/null || systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
  systemctl restart NetworkManager || true
fi

######################################################################################

step "Optional: key-only SSH (if SSH_KEY_PATH provided)"
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

######################################################################################

step "Enable GDM auto-login for user: $USERNAME"
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
    # WaylandEnable is handled only when the x11vnc setup below is requested.
  }
  print
}
END{ if(in_d){ if(!se) print "AutomaticLoginEnable=true"; if(!su) print "AutomaticLogin=" user } }
' "$GDM_CONF" > "$GDM_CONF.tmp" && mv "$GDM_CONF.tmp" "$GDM_CONF"

######################################################################################

step "Create default unencrypted GNOME keyring (no UI prompts)"
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

######################################################################################

if [ -n "${VNC_PASSWORD:-}" ]; then
  step "VNC / Remote Desktop server setup (backend: ${VNC_BACKEND})"
  USER_UID=$(id -u "$USERNAME")
  USER_ENV=("XDG_RUNTIME_DIR=/run/user/${USER_UID}" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${USER_UID}/bus")
  sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.config" || true

  # Force X11-only VNC regardless of requested backend.
  if [ "${VNC_BACKEND}" != "x11vnc" ]; then
    log " - Forcing VNC backend to x11vnc (Xorg only); ignoring requested backend."
    VNC_BACKEND="x11vnc"
  fi

  # --- X11-only VNC backend (x11vnc, shares X11 :0) ---
  # Ensure system uses Xorg for the login/user session.
  GDM_CONF="/etc/gdm3/custom.conf"
  if [ -f "$GDM_CONF" ]; then
    if grep -qE '^[#[:space:]]*WaylandEnable[[:space:]]*=' "$GDM_CONF"; then
      sed -i -E 's/^[#[:space:]]*WaylandEnable[[:space:]]*=.*/WaylandEnable=false/' "$GDM_CONF" || true
    else
      grep -q '^\[daemon\]' "$GDM_CONF" || printf '\n[daemon]\n' >> "$GDM_CONF"
      printf 'WaylandEnable=false\n' >> "$GDM_CONF"
    fi
  fi
  ACCOUNTS_USER_FILE="/var/lib/AccountsService/users/$USERNAME"
  install -d -m 0755 /var/lib/AccountsService/users 2>/dev/null || true
  touch "$ACCOUNTS_USER_FILE"
  XORG_SESSION=""
  if [ -f /usr/share/xsessions/ubuntu-xorg.desktop ]; then XORG_SESSION=ubuntu-xorg; fi
  if [ -z "$XORG_SESSION" ] && [ -f /usr/share/xsessions/ubuntu.desktop ]; then XORG_SESSION=ubuntu; fi
  if grep -q '^\[User\]' "$ACCOUNTS_USER_FILE"; then
    sed -i -E '/^(Session|XSession)=/d' "$ACCOUNTS_USER_FILE" || true
    printf 'XSession=%s\n' "${XORG_SESSION:-ubuntu}" >> "$ACCOUNTS_USER_FILE"
  else
    printf '[User]\nXSession=%s\n' "${XORG_SESSION:-ubuntu}" > "$ACCOUNTS_USER_FILE"
  fi

  apt_install_retry x11vnc || true

  if command -v x11vnc >/dev/null 2>&1; then
  # Determine VNC password: use --vnc-password, else existing seed, else existing system pass, else generate.
  VNC_PASS8="${VNC_PASSWORD:-}"
  if [ -z "$VNC_PASS8" ] && [ -s "$HOME_DIR/.config/gnome-remote-desktop.vncpass" ]; then
    VNC_PASS8=$(head -n1 "$HOME_DIR/.config/gnome-remote-desktop.vncpass")
  fi
  if [ -n "$VNC_PASS8" ]; then
    VNC_PASS8=$(printf '%s' "$VNC_PASS8" | LC_ALL=C tr -cd '[:print:]' | cut -b 1-8)
  fi
  if [ -z "$VNC_PASS8" ] && [ -f /etc/x11vnc.pass ]; then
    : # leave existing password file in place
  else
    if [ -z "$VNC_PASS8" ]; then
      VNC_PASS8=$(head -c 16 /dev/urandom | tr -cd 'A-Za-z0-9' | cut -c1-8)
      log " - Generated VNC password: ${VNC_PASS8} (stored to /etc/x11vnc.pass)"
      echo "$VNC_PASS8" > "$HOME_DIR/.config/vnc-password.txt"; chown "$USERNAME":"$USERNAME" "$HOME_DIR/.config/vnc-password.txt" || true
    fi
    # Store the VNC password hash deterministically (avoid stdin/verify pitfalls).
    x11vnc -storepasswd "$VNC_PASS8" /etc/x11vnc.pass >/dev/null 2>&1 || true
    # Record the effective 8-char VNC password for reference (insecure; stored in user config).
    printf '%s\n' "$VNC_PASS8" > "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
    chown "$USERNAME":"$USERNAME" "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
  fi
  if [ -f /etc/x11vnc.pass ]; then
    chmod 600 /etc/x11vnc.pass
    chown root:root /etc/x11vnc.pass
  else
    log " - WARNING: /etc/x11vnc.pass was not created; x11vnc may not be installed/configured."
  fi

  # Create a wrapper that discovers the active user DISPLAY dynamically.
  cat >/usr/local/sbin/x11vnc-wrapper.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VNC_PASS_FILE="/etc/x11vnc.pass"
LOG_FILE="/var/log/x11vnc.log"

# Prefer the primary interactive user configured at install time
PREFERRED_USER="__PREFERRED_USER__"

# Resolve target session and DISPLAY via loginctl (most reliable)
resolve_display() {
  local user="$1"
  local sid disp type state
  while read -r sid _ usr _; do
    [ "$usr" = "$user" ] || continue
    type=$(loginctl show-session "$sid" -p Type 2>/dev/null | cut -d= -f2)
    state=$(loginctl show-session "$sid" -p State 2>/dev/null | cut -d= -f2)
    disp=$(loginctl show-session "$sid" -p Display 2>/dev/null | cut -d= -f2)
    if [ "$type" = "x11" ] && [ "$state" = "active" ] && [ -n "$disp" ]; then
      printf '%s\n' "$disp"
      return 0
    fi
  done < <(loginctl list-sessions --no-legend 2>/dev/null)
  return 1
}

# Pick a user: preferred non-gdm user, else first non-gdm with an active x11 session
USER_NAME=""
if [ -n "$PREFERRED_USER" ] && [ "$PREFERRED_USER" != "gdm" ]; then
  USER_NAME="$PREFERRED_USER"
fi
if [ -z "$USER_NAME" ]; then
  USER_NAME=$(loginctl list-sessions --no-legend 2>/dev/null | awk '$3!="gdm" {print $3; exit}')
fi
[ -n "$USER_NAME" ] || USER_NAME="$(id -nu 1000 2>/dev/null || echo jetson)"
USER_UID=$(id -u "$USER_NAME")
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)

DISPLAY_VAL=""
if ! DISPLAY_VAL=$(resolve_display "$USER_NAME"); then
  # Fallback to reading gnome-shell env if loginctl provided none
  if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
    if [ -r "/proc/$pid/environ" ]; then
      DISPLAY_VAL=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="DISPLAY"{print $2; exit}')
      [ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"
    fi
  fi
fi
[ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"

# If the chosen DISPLAY socket doesn't exist, prefer the highest X socket available (e.g., :1 over :0)
sock="/tmp/.X11-unix/X${DISPLAY_VAL#:}"
if [ ! -S "$sock" ]; then
  best=""
  for s in /tmp/.X11-unix/X*; do
    [ -S "$s" ] || continue
    n=${s##*/X}
    case "$n" in (*[!0-9]*) continue;; esac
    if [ -z "$best" ] || [ "$n" -gt "$best" ]; then best="$n"; fi
  done
  if [ -n "$best" ]; then DISPLAY_VAL=":$best"; sock="/tmp/.X11-unix/X$best"; fi
fi

# Wait for matching X socket
for i in $(seq 1 120); do
  [ -S "$sock" ] && break
  sleep 1
done

# Determine XAUTHORITY (prefer user's cookie)
AUTH_ENV=""
if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
  if [ -r "/proc/$pid/environ" ]; then
    AUTH_ENV=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="XAUTHORITY"{print $2; exit}')
  fi
fi

# Try to extract the exact cookie for the chosen DISPLAY into a temporary auth file
AUTH_TMP="/run/x11vnc.${USER_UID}.auth"
rm -f "$AUTH_TMP" 2>/dev/null || true
if [ -n "$AUTH_ENV" ] && [ -f "$AUTH_ENV" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$AUTH_ENV' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
if [ ! -s "$AUTH_TMP" ] && [ -f "$HOME_DIR/.Xauthority" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$HOME_DIR/.Xauthority' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
chmod 600 "$AUTH_TMP" 2>/dev/null || true

# Final AUTH_FILE selection
AUTH_FILE="$AUTH_TMP"
if [ ! -s "$AUTH_FILE" ]; then
  AUTH_FILE="$HOME_DIR/.Xauthority"
fi
if [ ! -f "$AUTH_FILE" ]; then
  AUTH_FILE="/run/user/${USER_UID}/gdm/Xauthority"
fi

# Log selection for troubleshooting
{
  echo "[x11vnc-wrapper] USER=$USER_NAME UID=$USER_UID HOME=$HOME_DIR"
  echo "[x11vnc-wrapper] DISPLAY=$DISPLAY_VAL AUTH=$AUTH_FILE"
} >> "$LOG_FILE" 2>&1 || true

# Allow root to access the user's X server via xhost (avoids cookie mismatch)
su -s /bin/sh - "$USER_NAME" -c "DISPLAY='$DISPLAY_VAL' XAUTHORITY='${AUTH_ENV:-$HOME_DIR/.Xauthority}' xhost +SI:localuser:root" >>"$LOG_FILE" 2>&1 || true

# Build optional auth flag only if we have a non-empty cookie file
AUTH_OPT=""
if [ -s "$AUTH_FILE" ]; then AUTH_OPT="-auth $AUTH_FILE"; fi

# Run x11vnc pinned to the resolved DISPLAY with optional auth
exec /usr/bin/x11vnc \
  -display "$DISPLAY_VAL" \
  $AUTH_OPT \
  -forever -loop -noxdamage -repeat -xrandr \
  -rfbauth "$VNC_PASS_FILE" -rfbport 5900 -shared \
  -o "$LOG_FILE"
EOF
  # Inject the preferred user into the wrapper to avoid attaching to gdm.
  sed -i -E "s#__PREFERRED_USER__#${USERNAME}#" /usr/local/sbin/x11vnc-wrapper.sh
  chmod 0755 /usr/local/sbin/x11vnc-wrapper.sh

  # Systemd unit using the wrapper.
  cat >/etc/systemd/system/x11vnc.service <<'EOF'
[Unit]
Description=Legacy VNC server for X11 (x11vnc)
Requires=display-manager.service
After=display-manager.service graphical.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/x11vnc-wrapper.sh
Restart=always
RestartSec=2

[Install]
WantedBy=graphical.target
EOF

  systemctl daemon-reload
  systemctl enable --now x11vnc.service || true

  # Stop GNOME Remote Desktop to avoid port conflict.
  sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user disable --now gnome-remote-desktop.service 2>/dev/null || true
  sudo -u "$USERNAME" env "${USER_ENV[@]}" systemctl --user disable --now gnome-remote-desktop-headless.service 2>/dev/null || true
  log " - Set GDM to Xorg (WaylandEnable=false) and selected Xorg session. Reboot or log out/in to apply."

  # Open firewall for VNC (guard against duplicates)
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -q '5900/tcp'; then
      ufw allow 5900/tcp || true
    fi
  fi
  else
    log " - WARNING: x11vnc is not installed; skipping VNC password, wrapper, service, and firewall setup."
  fi
else
  step "VNC: no changes (run with --vnc-password=... to modify VNC settings)"
fi

######################################################################################

step "Rename device (hostname) if requested"
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

######################################################################################

step "Disable zram (nvzramconfig)"
if systemctl is-enabled nvzramconfig >/dev/null 2>&1; then
  systemctl disable nvzramconfig || true
  systemctl stop nvzramconfig || true
  log " - zram (nvzramconfig) disabled."
else
  log " - zram already disabled; skipping."
fi

######################################################################################

step "Install jetson-stats (jtop) via fix_jetson_stats.py"
JTOP_FIX_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fix_jetson_stats.py"
if [ -f "$JTOP_FIX_SCRIPT" ]; then
  if ! python3 "$JTOP_FIX_SCRIPT" --user "$USERNAME"; then
    log " - WARNING: fix_jetson_stats.py failed; inspect the output above."
  fi
else
  log " - WARNING: $JTOP_FIX_SCRIPT not found; skipping."
fi

######################################################################################

step "Configure swapfile (auto-default 8G/16G; disabled on Thor)"
if [ "${IS_THOR:-0}" -eq 1 ]; then
  log " - Thor detected; removing /swapfile and disabling swap at boot"
  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile || true
  if [ -f /etc/fstab ]; then
    sed -i -E '/^[[:space:]]*\/swapfile\b/d' /etc/fstab || true
  fi
  systemctl stop swapfile.swap 2>/dev/null || true
  systemctl disable swapfile.swap 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
else
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
fi

######################################################################################

step "Repair Git & Git LFS permissions for all repos under $HOME_DIR"
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

######################################################################################

step "Set Jetson power mode (Thor=1/120W, others=MAXN)"
if command -v nvpmodel >/dev/null 2>&1; then
  if [ "$IS_THOR" -eq 1 ] && [ "$IS_ORIN_NX_OR_NANO" -eq 0 ]; then
    # Jetson AGX Thor: always set mode 1 (120W)
    if timeout 5s nvpmodel -m 1 >/dev/null 2>&1; then
      sleep 1
      log " - Set AGX Thor nvpmodel mode to 1 (120W)"
      # Show the reported status for visibility (output format can vary)
      timeout 5s nvpmodel -q 2>/dev/null || true
    else
      log " - WARNING: failed to set nvpmodel mode 1 on Thor"
    fi
  else
    # Orin NX/Nano and other Jetson devices: try to select the highest MAXN profile.
    if timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
      log " - Power mode already MAXN; skipping."
    else
      # Commonly MAXN/MAXN_SUPER is mode 0 on Orin NX/Nano.
      if timeout 5s nvpmodel -m 0 >/dev/null 2>&1; then
        sleep 1
      fi
      if timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
        log " - Set power mode to MAXN via nvpmodel -m 0 (model: ${MODEL:-unknown})"
      else
        # Fallback: brute-force through modes 0-9 until MAXN is found
        for id in 1 2 3 4 5 6 7 8 9; do
          if timeout 5s nvpmodel -m "$id" >/dev/null 2>&1; then
            sleep 1
            if timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
              log " - Set power mode to MAXN via nvpmodel -m $id (fallback)"
              break
            fi
          fi
        done
        if ! timeout 5s nvpmodel -q 2>/dev/null | grep -qi 'MAXN'; then
          log " - WARNING: Could not detect MAXN after trying modes 0-9. Reported status:"
          timeout 5s nvpmodel -q 2>/dev/null || true
          log "   Check /etc/nvpmodel.conf for mode numbers."
        fi
      fi
    fi
  fi
else
  log " - nvpmodel not found; skipping."
fi

######################################################################################

step "Install Docker Engine and plugins (if missing)"
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
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
  systemctl enable --now docker || true
else
  if is_pkg_installed docker.io; then
    log " - docker.io detected; skipping Docker CE package upgrade to avoid a package migration."
  elif is_pkg_installed docker-ce; then
    log " - Docker CE already installed; ensuring plugins present"
    apt-get install -y docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras || true

    log " - Upgrading Docker Engine and plugins"
    # If running manually (non-root):
    # sudo apt-get install --only-upgrade -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
    if ! apt-get install --only-upgrade -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras; then
      log " - WARNING: Docker CE upgrade failed; leaving the existing Docker install in place."
    fi
  else
    log " - Existing Docker install is not managed by docker-ce packages; skipping package upgrade."
  fi
fi

######################################################################################

step "Configure Docker default runtime to NVIDIA"
DAEMON_JSON=/etc/docker/daemon.json
if ! command -v python3 >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y python3 || true
fi
NVIDIA_RUNTIME_AVAILABLE=0
if command -v nvidia-container-runtime >/dev/null 2>&1; then
  NVIDIA_RUNTIME_AVAILABLE=1
fi
python3 - "$DAEMON_JSON" "$NVIDIA_RUNTIME_AVAILABLE" <<'PY'
import json, os, sys

path = sys.argv[1]
enable_nvidia = sys.argv[2] == '1'
data = {}
try:
    if os.path.exists(path):
        with open(path, 'r') as f:
            data = json.load(f)
except Exception:
    data = {}

runtimes = data.get('runtimes', {})
if enable_nvidia:
    nvidia = runtimes.get('nvidia', {})
    nvidia['path'] = 'nvidia-container-runtime'
    nvidia['runtimeArgs'] = nvidia.get('runtimeArgs', [])
    runtimes['nvidia'] = nvidia
    data['runtimes'] = runtimes
    data['default-runtime'] = 'nvidia'
else:
    if data.get('default-runtime') == 'nvidia':
        data.pop('default-runtime', None)
    if runtimes:
        data['runtimes'] = runtimes

os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=False)
os.replace(tmp, path)
PY
systemctl daemon-reload || true
systemctl restart docker || true
if [ "$NVIDIA_RUNTIME_AVAILABLE" -eq 1 ]; then
  log " - Ensured NVIDIA runtime in $DAEMON_JSON and restarted Docker"
else
  log " - NVIDIA container runtime not found; left Docker on a non-NVIDIA default runtime."
fi

######################################################################################

step "Ensure $USERNAME is in 'docker' group"
if ! getent group docker >/dev/null; then
  groupadd docker || true
fi
if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx docker; then
  log " - $USERNAME already in docker group; skipping."
else
  usermod -aG docker "$USERNAME" || true
  log " - Added $USERNAME to docker group. You may need to log out/in for group changes to take effect."
fi

######################################################################################

step "Remove preinstalled games (apt & snap)"

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

######################################################################################

step "Install MicroK8s (snap) [optional]"
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
    # Ensure the target user's .bashrc also has the alias (idempotent)
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

######################################################################################

# Clone jetson-containers and run install.sh (only if missing)
step "Clone jetson-containers and run install.sh (only if missing)"
# Ensure git is available
if ! command -v git >/dev/null 2>&1; then
  apt-get install -y git
fi

TARGET_DIR="$HOME_DIR/git/jetson-containers"
install -d -m 0755 -o "$USERNAME" -g "$USERNAME" "$HOME_DIR/git"
if [ -d "$TARGET_DIR" ]; then
  log " - $TARGET_DIR already exists; skipping clone and install.sh"
else
  log " - Cloning jetson-containers"
  sudo -u "$USERNAME" git clone --recursive https://github.com/dusty-nv/jetson-containers "$TARGET_DIR" || true
  # Run install.sh if present after clone
  if [ -x "$TARGET_DIR/install.sh" ]; then
    sudo -u "$USERNAME" bash -lc "cd '$TARGET_DIR' && ./install.sh" || true
  else
    log " - WARNING: install.sh not found or not executable at $TARGET_DIR after clone"
  fi
fi

######################################################################################

# Install K3s [optional]
step "Install K3s [optional]"
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

  # Ensure kube config directory for the target user
  sudo -u "$USERNAME" install -d -m 0700 "$HOME_DIR/.kube" || true
  chown -R "$USERNAME":"$USERNAME" "$HOME_DIR/.kube" || true

  # Install K3s using Docker and write kubeconfig to user's home, passing --node-ip/--advertise-address if available
  K3S_INSTALL_ARGS="server --docker --write-kubeconfig-mode 644 --write-kubeconfig '$HOME_DIR/.kube/config'"
  if [ -n "$NODE_IP" ]; then
    K3S_INSTALL_ARGS="$K3S_INSTALL_ARGS --node-ip $NODE_IP --advertise-address $NODE_IP"
  fi
  if ! command -v k3s >/dev/null 2>&1; then
    sh -c "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=\"$K3S_INSTALL_ARGS\" sh -s -" || true
  else
    log " - K3s already installed; skipping install script"
  fi

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

######################################################################################

step "Install Helm (Kubernetes package manager) [optional]"
if [ "${K3S}" -eq 1 ]; then
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
else
  log " - Skipping Helm install (requires --k3s)"
fi

######################################################################################

step "Install guvcview"
apt-get install -y guvcview

######################################################################################

step "Configure local registry (optional)"
if [ -n "${REG_IP:-}" ]; then
  # Basic IPv4 sanity check (do not hard fail if mismatched)
  if echo "$REG_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    log " - Using registry IP: $REG_IP"

    # Add/replace registry.local in /etc/hosts
    if [ -f /etc/hosts ]; then
      cp /etc/hosts "/etc/hosts.bak.$(date +%s)" || true
      awk 'index($0,"registry.local")==0' /etc/hosts > /etc/hosts.tmp && \
        printf "%s registry.local\n" "$REG_IP" >> /etc/hosts.tmp && \
        mv /etc/hosts.tmp /etc/hosts
    else
      printf "%s registry.local\n" "$REG_IP" > /etc/hosts
    fi
    log " - Mapped registry.local to $REG_IP in /etc/hosts"

    # Install domain.crt for Docker registry.local on the expected registry ports.
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CERT_SRC="$SCRIPT_DIR/domain.crt"
    if [ -f "$CERT_SRC" ]; then
      for d in \
        /etc/docker/certs.d/registry.local:5001 \
        /etc/docker/certs.d/registry.local:5002 \
        /etc/docker/certs.d/registry.local:5003 \
        /etc/docker/certs.d/registry.local:5555; do
        install -d -m 0755 "$d" || true
      done
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5001/ca.crt
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5002/ca.crt
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5003/ca.crt
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5555/ca.crt
      chmod 644 /etc/docker/certs.d/registry.local:5001/ca.crt || true
      chmod 644 /etc/docker/certs.d/registry.local:5002/ca.crt || true
      chmod 644 /etc/docker/certs.d/registry.local:5003/ca.crt || true
      chmod 644 /etc/docker/certs.d/registry.local:5555/ca.crt || true
      log " - Installed domain.crt to Docker certs.d for registry.local"
    else
      log " - WARNING: domain.crt not found at $CERT_SRC; skipping cert installation"
    fi

    # Add the registry CA to the OS trust store (Ubuntu) if not already there.
    ca_src=""
    if [ -f "$CERT_SRC" ]; then
      ca_src="$CERT_SRC"
    else
      for candidate in \
        /etc/docker/certs.d/registry.local:5001/ca.crt \
        /etc/docker/certs.d/registry.local:5002/ca.crt \
        /etc/docker/certs.d/registry.local:5555/ca.crt; do
        if [ -f "$candidate" ]; then
          ca_src="$candidate"
          break
        fi
      done
    fi

    if [ -n "$ca_src" ]; then
      os_ca_dst="/usr/local/share/ca-certificates/registry-rca.crt"
      if [ ! -f "$os_ca_dst" ] || ! cmp -s "$ca_src" "$os_ca_dst"; then
        install -m 0644 "$ca_src" "$os_ca_dst"
        if ! command -v update-ca-certificates >/dev/null 2>&1; then
          apt_install_retry ca-certificates || apt-get install -y ca-certificates || true
        fi
        update-ca-certificates || true
        log " - Installed registry CA into OS trust store ($os_ca_dst)"
      else
        log " - Registry CA already present in OS trust store ($os_ca_dst); skipping update"
      fi

      # Verify it was picked up
      ls -l /etc/ssl/certs | grep -i registry || true
    else
      log " - WARNING: no registry CA cert available to add to OS trust store"
    fi

    # Ensure Docker daemon.json has registry mirrors.
    DAEMON_JSON=/etc/docker/daemon.json
    if ! command -v python3 >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y python3 || true
    fi
    python3 - "$DAEMON_JSON" <<'PY'
import json, os, sys

path = sys.argv[1]
data = {}
try:
    if os.path.exists(path):
        with open(path, 'r') as f:
            data = json.load(f)
except Exception:
    data = {}

mirrors = data.get('registry-mirrors', [])
required = [
    'https://registry.local:5001',
    'https://registry.local:5002',
]
for m in required:
    if m not in mirrors:
        mirrors.append(m)
data['registry-mirrors'] = mirrors

tmp = path + '.tmp'
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(tmp, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=False)
os.replace(tmp, path)
PY
    systemctl daemon-reload || true
    systemctl restart docker || true
    log " - Ensured registry mirrors in $DAEMON_JSON and restarted Docker"
  else
    log " - WARNING: REG provided but not an IPv4 address: $REG_IP"
  fi
else
  log " - Skipping registry setup (provide REG=IP or --reg=IP)"
fi

######################################################################################

step "Install NVM + Node LTS + OpenAI Codex CLI"
sudo -u "$USERNAME" bash -lc '
set -e
export NVM_DIR="$HOME/.nvm"
if [ ! -s "$NVM_DIR/nvm.sh" ]; then
  echo " - Installing nvm to $NVM_DIR"
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
# Ensure LTS Node is present and default
nvm install --lts
nvm alias default "lts/*" || true
nvm use --lts
# Install Codex CLI only if missing
if ! npm list -g @openai/codex >/dev/null 2>&1; then
  npm i -g @openai/codex
fi
# Show versions for verification
node -v || true
npm -v || true
'

######################################################################################

step "Configure Git identity (optional)"
if [ -n "${GIT_USER:-}" ] || [ -n "${GIT_EMAIL:-}" ]; then
  if ! command -v git >/dev/null 2>&1; then
    log " - git not installed; skipping identity configuration"
  elif [ -z "${GIT_USER:-}" ] || [ -z "${GIT_EMAIL:-}" ]; then
    log " - WARNING: both --git-user and --git-email must be provided; skipping."
  else
    log " - Setting git user.name to '$GIT_USER' and user.email to '$GIT_EMAIL'"
    sudo -u "$USERNAME" git config --global user.name "$GIT_USER"
    sudo -u "$USERNAME" git config --global user.email "$GIT_EMAIL"
  fi
else
  log " - Skipping Git identity configuration (provide --git-user and --git-email)"
fi

######################################################################################

step "Install btop (system monitor)"
if command -v btop >/dev/null 2>&1; then
  log " - btop already installed; skipping."
else
  apt-get update -y
  apt-get install -y btop
fi

######################################################################################

if [ "$REBOOT" -eq 1 ]; then
  log "Final: rebooting now to apply Xorg changes…"
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested."
  echo "Xorg drop-ins take effect after a restart of the display server; a full reboot is simplest."
  echo "Reboot later with: sudo systemctl reboot"
fi
