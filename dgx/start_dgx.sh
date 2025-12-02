#!/usr/bin/env bash

set -euo pipefail

# Require root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: this script must be run as root (use sudo)." >&2
  exit 1
fi

REBOOT=${REBOOT:-0}
REG_IP=${REG_IP:-${REG:-}}
GIT_USER=${GIT_USER:-}
GIT_EMAIL=${GIT_EMAIL:-}

usage() {
  echo "Usage: $0 [--reboot|--no-reboot] [--mks] [--k3s] [--hostname=NAME] [REG=IP|--reg=IP] [--git-user=NAME --git-email=EMAIL]"
}

for arg in "$@"; do
  case "$arg" in
    --reboot|-r) REBOOT=1 ;;
    --no-reboot) REBOOT=0 ;;
    --hostname=*|--set-hostname=*) NEW_HOSTNAME="${arg#*=}" ;;
    --mks) MICROK8S=1 ;;
    --k3s) K3S=1 ;;
    --git-user=*) GIT_USER="${arg#*=}" ;;
    --git-email=*) GIT_EMAIL="${arg#*=}" ;;
    REG=*) REG_IP="${arg#*=}" ;;
    --reg=*) REG_IP="${arg#*=}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option '$arg'" >&2; usage; exit 1 ;;
  esac
done

log(){ printf '\n=== %s ===\n' "$*"; }

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  TARGET_OS="${PRETTY_NAME:-${NAME:-unknown}}"
else
  TARGET_OS="$(uname -sr)"
fi
log "Target OS: ${TARGET_OS}"

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


log "1) Rename device (hostname) if requested"
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


log "2) Repair Git & Git LFS permissions for all repos under $HOME_DIR"
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


log "3) Configure Git identity (optional)"
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


log "4) Configure Docker default runtime to NVIDIA"
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

log "5) Ensure $USERNAME is in 'docker' group"
if ! getent group docker >/dev/null; then
  groupadd docker || true
fi
if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx docker; then
  log " - $USERNAME already in docker group; skipping."
else
  usermod -aG docker "$USERNAME" || true
  log " - Added $USERNAME to docker group. You may need to log out/in for group changes to take effect."
fi


log "6) Install MicroK8s (snap) [optional]"
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


log "7) Install K3s [optional]"
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
  log "8) Install Helm (Kubernetes package manager)"
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


log "9) Configure local registry (optional)"
if [ -n "${REG_IP:-}" ]; then
  # Basic IPv4 sanity check (do not hard fail if mismatched)
  if echo "$REG_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    log " - Using registry IP: $REG_IP"

    # 8.1) Add/replace registry.local in /etc/hosts
    if [ -f /etc/hosts ]; then
      cp /etc/hosts "/etc/hosts.bak.$(date +%s)" || true
      awk 'index($0,"registry.local")==0' /etc/hosts > /etc/hosts.tmp && \
        printf "%s registry.local\n" "$REG_IP" >> /etc/hosts.tmp && \
        mv /etc/hosts.tmp /etc/hosts
    else
      printf "%s registry.local\n" "$REG_IP" > /etc/hosts
    fi
    log " - Mapped registry.local to $REG_IP in /etc/hosts"

    # 8.2) Install domain.crt for Docker registry.local on ports 5001/5002/5555
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CERT_SRC="$SCRIPT_DIR/../src/domain.crt"
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

    # 8.3) Ensure Docker daemon.json has registry mirrors
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


log "10) Install NVM + Node LTS + OpenAI Codex CLI"
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

log "11) Install btop (system monitor)"
if command -v btop >/dev/null 2>&1; then
  log " - btop already installed; skipping."
else
  apt-get update -y
  apt-get install -y btop
fi


if [ "$REBOOT" -eq 1 ]; then
  log "Final: rebooting now to apply display/login changes…"
  sleep 2
  systemctl reboot
else
  log "Final: reboot NOT requested."
  echo "Display manager changes take effect after restarting the graphical session; reboot when convenient."
  echo "Reboot later with: sudo systemctl reboot"
fi
