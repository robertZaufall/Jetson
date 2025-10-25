#!/usr/bin/env bash

set -euo pipefail

# Require root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: this script must be run as root (use sudo)." >&2
  exit 1
fi

REBOOT=${REBOOT:-0}
REG_IP=${REG_IP:-${REG:-}}

usage() {
  echo "Usage: $0 [--reboot|--no-reboot] [--mks] [--k3s] [--vnc-password=PASS] [--hostname=NAME] [REG=IP|--reg=IP]"
}

for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --vnc-password=*|--vnc-pass=*) VNC_PASSWORD="${arg#*=}" ;;
    --hostname=*|--set-hostname=*) NEW_HOSTNAME="${arg#*=}" ;;
    --mks) MICROK8S=1 ;;
    --k3s) K3S=1 ;;
    REG=*) REG_IP="${arg#*=}" ;;
    --reg=*) REG_IP="${arg#*=}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option '$arg'" >&2; usage; exit 1 ;;
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }

# Small helpers
apt_install_retry() {
  # Usage: apt_install_retry pkg1 [pkg2 ...]
  # Be resilient to transient DNS/network hiccups
  DEBIAN_FRONTEND=noninteractive apt-get update -y -o Acquire::Retries=3 \
    -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Acquire::Retries=3 "$@" || return 1
}

VNC_BACKEND="x11vnc"

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  TARGET_OS="${PRETTY_NAME:-${NAME:-unknown}}"
else
  TARGET_OS="$(uname -sr)"
fi
log "Target OS: ${TARGET_OS}; VNC backend: ${VNC_BACKEND}"

MICROK8S=${MICROK8S:-0}
K3S=${K3S:-0}

resolve_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then printf '%s' "$SUDO_USER"; return; fi
  if logname >/dev/null 2>&1; then ln=$(logname 2>/dev/null || true); [ -n "$ln" ] && [ "$ln" != "root" ] && { printf '%s' "$ln"; return; }; fi
  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}
USERNAME="$(resolve_user)"
[ -n "$USERNAME" ] || { echo "ERROR: could not resolve a non-root user." >&2; exit 1; }
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
log "Target user: $USERNAME ($HOME_DIR)"


log "3) Configure x11vnc remote desktop"
if [ -n "${VNC_PASSWORD:-}" ]; then
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
  GNOME_SESSION=""
  if [ -f /usr/share/xsessions/gnome.desktop ]; then GNOME_SESSION=gnome; fi
  if [ -z "$GNOME_SESSION" ] && [ -f /usr/share/xsessions/ubuntu.desktop ]; then GNOME_SESSION=ubuntu; fi
  CURRENT_SESSION=""
  if [ -s "$ACCOUNTS_USER_FILE" ]; then
    CURRENT_SESSION=$(awk '
      /^[[:space:]]*(Session|XSession)[[:space:]]*=/{
        sub(/^[[:space:]]*(Session|XSession)[[:space:]]*=[[:space:]]*/, "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        if ($0 != "") { print $0; exit }
      }
    ' "$ACCOUNTS_USER_FILE" 2>/dev/null || true)
  fi
  if [ -n "$CURRENT_SESSION" ]; then
    log " - Existing desktop session entry: $CURRENT_SESSION"
  fi

  SESSION_TO_WRITE=""
  for candidate in "$CURRENT_SESSION" nvidia "$GNOME_SESSION" gnome gnome-xorg ubuntu ubuntu-xorg; do
    [ -n "$candidate" ] || continue
    if [ -f "/usr/share/xsessions/${candidate}.desktop" ]; then
      SESSION_TO_WRITE="$candidate"
      break
    fi
  done

  if [ -n "$SESSION_TO_WRITE" ]; then
    if [ "$SESSION_TO_WRITE" = "$CURRENT_SESSION" ] && [ -n "$CURRENT_SESSION" ]; then
      log " - Preserving AccountsService session '$SESSION_TO_WRITE'"
    else
      log " - Setting AccountsService session to '$SESSION_TO_WRITE'"
    fi

    if grep -q '^\[User\]' "$ACCOUNTS_USER_FILE"; then
      if grep -q '^[#[:space:]]*XSession[[:space:]]*=' "$ACCOUNTS_USER_FILE"; then
        sed -i -E 's/^[#[:space:]]*XSession[[:space:]]*=.*/XSession='"$SESSION_TO_WRITE"'/' "$ACCOUNTS_USER_FILE" || true
      else
        printf 'XSession=%s\n' "$SESSION_TO_WRITE" >> "$ACCOUNTS_USER_FILE"
      fi
    else
      printf '[User]\nXSession=%s\n' "$SESSION_TO_WRITE" > "$ACCOUNTS_USER_FILE"
    fi
  else
    log " - WARNING: could not locate a valid desktop session entry; leaving AccountsService untouched"
  fi

  apt_install_retry x11vnc || true

  VNC_PASS8=$(printf '%s' "$VNC_PASSWORD" | LC_ALL=C tr -cd '[:print:]' | cut -b 1-8)
  if [ -z "$VNC_PASS8" ]; then
    echo "ERROR: --vnc-password must contain at least one printable character." >&2
    exit 1
  fi

  x11vnc -storepasswd "$VNC_PASS8" /etc/x11vnc.pass >/dev/null 2>&1 || true
  printf '%s\n' "$VNC_PASS8" > "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
  chown "$USERNAME":"$USERNAME" "$HOME_DIR/.config/vnc-password.txt" 2>/dev/null || true
  chmod 600 /etc/x11vnc.pass && chown root:root /etc/x11vnc.pass

  cat >/usr/local/sbin/x11vnc-wrapper.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VNC_PASS_FILE="/etc/x11vnc.pass"
LOG_FILE="/var/log/x11vnc.log"

PREFERRED_USER="__PREFERRED_USER__"

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

USER_NAME=""
if [ -n "$PREFERRED_USER" ] && [ "$PREFERRED_USER" != "gdm" ]; then
  USER_NAME="$PREFERRED_USER"
fi
if [ -z "$USER_NAME" ]; then
USER_NAME=$(loginctl list-sessions --no-legend 2>/dev/null | awk '$3!="gdm" {print $3; exit}')
fi
[ -n "$USER_NAME" ] || USER_NAME="$(id -nu 1000 2>/dev/null || echo dgx)"
USER_UID=$(id -u "$USER_NAME")
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)

DISPLAY_VAL=""
if ! DISPLAY_VAL=$(resolve_display "$USER_NAME"); then
  if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
    if [ -r "/proc/$pid/environ" ]; then
      DISPLAY_VAL=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="DISPLAY"{print $2; exit}')
      [ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"
    fi
  fi
fi
[ -n "$DISPLAY_VAL" ] || DISPLAY_VAL=":0"

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

for _ in $(seq 1 120); do
  [ -S "$sock" ] && break
  sleep 1
done

AUTH_ENV=""
if pid=$(pgrep -u "$USER_NAME" -x gnome-shell | head -n1 2>/dev/null || true); then
  if [ -r "/proc/$pid/environ" ]; then
    AUTH_ENV=$(tr '\0' '\n' </proc/$pid/environ | awk -F= '$1=="XAUTHORITY"{print $2; exit}')
  fi
fi

AUTH_TMP="/run/x11vnc.${USER_UID}.auth"
rm -f "$AUTH_TMP" 2>/dev/null || true
if [ -n "$AUTH_ENV" ] && [ -f "$AUTH_ENV" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$AUTH_ENV' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
if [ ! -s "$AUTH_TMP" ] && [ -f "$HOME_DIR/.Xauthority" ]; then
  su -s /bin/sh - "$USER_NAME" -c "XAUTHORITY='$HOME_DIR/.Xauthority' xauth extract '$AUTH_TMP' '$DISPLAY_VAL'" >>"$LOG_FILE" 2>&1 || true
fi
chmod 600 "$AUTH_TMP" 2>/dev/null || true

AUTH_FILE="$AUTH_TMP"
if [ ! -s "$AUTH_FILE" ]; then
  AUTH_FILE="$HOME_DIR/.Xauthority"
fi
if [ ! -f "$AUTH_FILE" ]; then
  AUTH_FILE="/run/user/${USER_UID}/gdm/Xauthority"
fi

{
  echo "[x11vnc-wrapper] USER=$USER_NAME UID=$USER_UID HOME=$HOME_DIR"
  echo "[x11vnc-wrapper] DISPLAY=$DISPLAY_VAL AUTH=$AUTH_FILE"
} >> "$LOG_FILE" 2>&1 || true

su -s /bin/sh - "$USER_NAME" -c "DISPLAY='$DISPLAY_VAL' XAUTHORITY='${AUTH_ENV:-$HOME_DIR/.Xauthority}' xhost +SI:localuser:root" >>"$LOG_FILE" 2>&1 || true

AUTH_OPT=""
if [ -s "$AUTH_FILE" ]; then AUTH_OPT="-auth $AUTH_FILE"; fi

# -noshm prevents MIT-SHM BadAccess crashes on remote/virtual X servers.
exec /usr/bin/x11vnc \
  -display "$DISPLAY_VAL" \
  $AUTH_OPT \
  -forever -loop -noxdamage -noshm -repeat -xrandr \
  -rfbauth "$VNC_PASS_FILE" -rfbport 5900 -shared \
  -o "$LOG_FILE"
EOF
  sed -i -E "s#__PREFERRED_USER__#${USERNAME}#" /usr/local/sbin/x11vnc-wrapper.sh
  chmod 0755 /usr/local/sbin/x11vnc-wrapper.sh

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

  log " - Set GDM to GNOME on X11 (WaylandEnable=false) and selected GNOME session. Reboot or log out/in to apply."

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | grep -q '5900/tcp'; then
      ufw allow 5900/tcp || true
    fi
  fi
else
  log " - Skipping VNC setup (provide --vnc-password=... to enable x11vnc)"
fi



log "4) Rename device (hostname) if requested"
if [ -n "${NEW_HOSTNAME:-}" ]; then
  if ! echo "$NEW_HOSTNAME" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'; then
    echo "ERROR: --hostname must be a valid RFC1123 hostname (letters, digits, hyphens; labels 1-63 chars; cannot start/end with hyphen)." >&2
    exit 1
  fi

  log " - Setting hostname via hostnamectl to '$NEW_HOSTNAME'"
  hostnamectl set-hostname "$NEW_HOSTNAME" || { echo "ERROR: failed to set hostname" >&2; exit 1; }

  short_name="${NEW_HOSTNAME%%.*}"
  hosts_line="127.0.1.1 ${NEW_HOSTNAME}"
  if [ "$short_name" != "$NEW_HOSTNAME" ]; then
    hosts_line="${hosts_line} ${short_name}"
  fi

  if grep -qE '^127\\.0\\.1\\.1\\b' /etc/hosts; then
    sed -i -E "s/^127\\.0\\.1\\.1\\s+.*/${hosts_line//\//\/}/" /etc/hosts
  else
    printf '%s\n' "$hosts_line" >> /etc/hosts
  fi

  log " - Hostname set. New /etc/hosts entry: $(grep -E '^127\\.0\\.1\\.1\\b' /etc/hosts || true)"
else
  log " - Hostname unchanged (no --hostname provided)"
fi

log "5) Repair Git & Git LFS permissions for all repos under $HOME_DIR"
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

log "6) Configure Docker default runtime to NVIDIA"
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

# Ensure NVIDIA runtime is configured
runtimes = data.get('runtimes', {})
nvidia = runtimes.get('nvidia', {})
nvidia['path'] = 'nvidia-container-runtime'
nvidia['runtimeArgs'] = nvidia.get('runtimeArgs', [])
runtimes['nvidia'] = nvidia
data['runtimes'] = runtimes
data['default-runtime'] = 'nvidia'

os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=False)
os.replace(tmp, path)
PY
systemctl daemon-reload || true
systemctl restart docker || true
log " - Ensured NVIDIA runtime in $DAEMON_JSON and restarted Docker"

log "7) Ensure $USERNAME is in 'docker' group"
if ! getent group docker >/dev/null; then
  groupadd docker || true
fi
if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx docker; then
  log " - $USERNAME already in docker group; skipping."
else
  usermod -aG docker "$USERNAME" || true
  log " - Added $USERNAME to docker group. You may need to log out/in for group changes to take effect."
fi


log "8) Install MicroK8s (snap) [optional]"
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


log "9) Install K3s [optional]"
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


if [ "${K3S}" -eq 1 ]; then
  log "10) Install Helm (Kubernetes package manager)"
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


log "11) Configure local registry (optional)"
if [ -n "${REG_IP:-}" ]; then
  # Basic IPv4 sanity check (do not hard fail if mismatched)
  if echo "$REG_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    log " - Using registry IP: $REG_IP"

    # 11.1) Add/replace registry.local in /etc/hosts
    if [ -f /etc/hosts ]; then
      cp /etc/hosts "/etc/hosts.bak.$(date +%s)" || true
      awk 'index($0,"registry.local")==0' /etc/hosts > /etc/hosts.tmp && \
        printf "%s registry.local\n" "$REG_IP" >> /etc/hosts.tmp && \
        mv /etc/hosts.tmp /etc/hosts
    else
      printf "%s registry.local\n" "$REG_IP" > /etc/hosts
    fi
    log " - Mapped registry.local to $REG_IP in /etc/hosts"

    # 11.2) Install domain.crt for Docker registry.local on ports 5001/5002/5555
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CERT_SRC="$SCRIPT_DIR/domain.crt"
    if [ -f "$CERT_SRC" ]; then
      for d in \
        /etc/docker/certs.d/registry.local:5001 \
        /etc/docker/certs.d/registry.local:5002 \
        /etc/docker/certs.d/registry.local:5555; do
        install -d -m 0755 "$d" || true
      done
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5001/ca.crt
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5002/ca.crt
      cp "$CERT_SRC" /etc/docker/certs.d/registry.local:5555/ca.crt
      chmod 644 /etc/docker/certs.d/registry.local:5001/ca.crt || true
      chmod 644 /etc/docker/certs.d/registry.local:5002/ca.crt || true
      chmod 644 /etc/docker/certs.d/registry.local:5555/ca.crt || true
      log " - Installed domain.crt to Docker certs.d for registry.local"
    else
      log " - WARNING: domain.crt not found at $CERT_SRC; skipping cert installation"
    fi

    # 11.3) Ensure Docker daemon.json has registry mirrors
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


log "12) Install NVM + Node LTS + OpenAI Codex CLI"
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


if [ "$REBOOT" -eq 1 ]; then
  log "Final: rebooting now to apply display/login changes…"
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested."
  echo "Display manager changes take effect after restarting the graphical session; reboot when convenient."
  echo "Reboot later with: sudo systemctl reboot"
fi
