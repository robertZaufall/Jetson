#!/usr/bin/env bash

# Steps:
# 1. Validate the required default user, password, and hostname arguments.
# 2. Resolve the latest JetPack 7 AGX Thor `Linux_for_Tegra` directory and target rootfs.
# 3. Apply NVIDIA binaries and run flash prerequisites in the JetPack workspace.
# 4. Pre-create the default user account and hostname in the target image.
# 5. Optionally inject a Wi-Fi profile into the target rootfs.
# 6. Preinstall and enable the SSH server for the target, with a first-boot fallback.
# 7. Preseed a German keyboard layout for the system, GNOME, and GDM in the target rootfs.
# 8. Keep the target locale non-German so only the keyboard layout changes.
# 9. Suppress GNOME's first-login welcome flow in the target image.
# 10. Optionally enter the rootfs with qemu-user-static to compile dconf defaults and refresh keyboard settings.
# 11. Seed a `clone.sh` helper into `/etc/skel` and the default user's home directory.
# 12. Flash the Jetson AGX Thor devkit image with `l4t_initrd_flash.sh`.

set -euo pipefail

usage() {
  echo "Usage: $0 <default-user-name> <default-user-password> <default-hostname> [--wifi-ssid=SSID] [--wifi-psk=PASS]" >&2
}

if [[ $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
  usage
  exit 0
fi

if [[ $# -lt 3 ]]; then
  usage
  exit 1
fi

USER_NAME="$1"
USER_PASSWORD="$2"
TARGET_HOSTNAME="$3"
WIFI_SSID="${WIFI_SSID:-}"
WIFI_PSK="${WIFI_PSK:-${WIFI_PASSWORD:-}}"
shift 3

for arg in "$@"; do
  case "$arg" in
    --wifi-ssid=*)
      WIFI_SSID="${arg#*=}"
      ;;
    --wifi-psk=*|--wifi-password=*)
      WIFI_PSK="${arg#*=}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      usage
      exit 1
      ;;
  esac
done

detect_host_wifi_ssid() {
  if command -v nmcli >/dev/null 2>&1; then
    nmcli -t -f ACTIVE,SSID dev wifi 2>/dev/null | awk -F: '$1=="yes"{print substr($0,5); exit}'
    return
  fi
  if command -v iwgetid >/dev/null 2>&1; then
    iwgetid -r 2>/dev/null || true
  fi
}

escape_nm_value() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//$'\n'/\\n}
  printf '%s' "$value"
}

WIFI_PROFILE_ENABLED=0
if [[ -n "$WIFI_PSK" ]]; then
  if [[ -z "$WIFI_SSID" ]]; then
    WIFI_SSID="$(detect_host_wifi_ssid)"
  fi
  if [[ -z "$WIFI_SSID" ]]; then
    echo "Wi-Fi password was provided, but no SSID was given and no active host Wi-Fi SSID could be detected." >&2
    echo "Pass --wifi-ssid=SSID explicitly." >&2
    exit 1
  fi
  WIFI_PROFILE_ENABLED=1
elif [[ -n "$WIFI_SSID" ]]; then
  echo "Wi-Fi SSID was provided without a password. Pass --wifi-psk=PASS as well." >&2
  exit 1
fi

#export JETPACK="$HOME/nvidia/nvidia_sdk/JetPack_7.0_Linux_JETSON_AGX_THOR_TARGETS/Linux_for_Tegra"
export JETPACK="$(ls -d "$HOME"/nvidia/nvidia_sdk/JetPack_7.*_Linux_JETSON_AGX_THOR_TARGETS/Linux_for_Tegra | tail -n1)"
ROOTFS="$JETPACK/rootfs"
USER_HOME_DIR="$ROOTFS/home/$USER_NAME"

cd "$JETPACK"
sudo ./apply_binaries.sh --openrm
sudo ./tools/l4t_flash_prerequisites.sh
#LC_ALL=C.UTF-8 LANG=C.UTF-8 sudo ./tools/l4t_create_default_user.sh -u "$USER_NAME" -p "$USER_PASSWORD" -a -n "$TARGET_HOSTNAME" --accept-license
sudo ./tools/l4t_create_default_user.sh -u "$USER_NAME" -p "$USER_PASSWORD" -a -n "$TARGET_HOSTNAME" --accept-license

seed_wifi_profile() {
  local ssid="$1"
  local psk="$2"
  local safe_name conn_id conn_uuid conn_file

  safe_name="$(printf '%s' "$ssid" | tr -cs '[:alnum:]._-' '_')"
  safe_name="${safe_name#_}"
  safe_name="${safe_name%_}"
  [[ -n "$safe_name" ]] || safe_name="preseeded-wifi"

  conn_id="wifi-${safe_name}"
  conn_uuid="$(cat /proc/sys/kernel/random/uuid)"
  conn_file="$ROOTFS/etc/NetworkManager/system-connections/${conn_id}.nmconnection"

  sudo install -d -m 0700 "$ROOTFS/etc/NetworkManager/system-connections"
  sudo tee "$conn_file" >/dev/null <<EOF
[connection]
id=$conn_id
uuid=$conn_uuid
type=wifi
autoconnect=true
autoconnect-priority=100

[wifi]
mode=infrastructure
ssid=$(escape_nm_value "$ssid")

[wifi-security]
auth-alg=open
key-mgmt=wpa-psk
psk=$(escape_nm_value "$psk")

[ipv4]
method=auto

[ipv6]
addr-gen-mode=stable-privacy
method=auto

[proxy]
EOF
  sudo chmod 600 "$conn_file"
}

if [[ "$WIFI_PROFILE_ENABLED" -eq 1 ]]; then
  seed_wifi_profile "$WIFI_SSID" "$WIFI_PSK"
fi

seed_first_boot_ssh_service() {
  local script_path service_path wants_path

  script_path="$ROOTFS/usr/local/sbin/jetson-enable-ssh.sh"
  service_path="$ROOTFS/etc/systemd/system/jetson-enable-ssh.service"
  wants_path="$ROOTFS/etc/systemd/system/multi-user.target.wants/jetson-enable-ssh.service"

  sudo install -d "$ROOTFS/usr/local/sbin" "$ROOTFS/etc/systemd/system" "$ROOTFS/etc/systemd/system/multi-user.target.wants"
  sudo tee "$script_path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

done_marker="/var/lib/jetson-firstboot/ssh-ready"
install -d "$(dirname "$done_marker")"

status="$(dpkg-query -W -f='${Status}' openssh-server 2>/dev/null || true)"
if ! printf '%s' "$status" | grep -q 'install ok installed'; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y openssh-server
fi

rm -f /etc/ssh/ssh_host_*
ssh-keygen -A
systemctl enable ssh || true
systemctl restart ssh || systemctl start ssh || true
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow OpenSSH || true
fi

touch "$done_marker"
EOF
  sudo chmod 755 "$script_path"

  sudo tee "$service_path" >/dev/null <<'EOF'
[Unit]
Description=Install and enable OpenSSH on first boot
Wants=network-online.target
After=network-online.target
ConditionPathExists=!/var/lib/jetson-firstboot/ssh-ready

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/jetson-enable-ssh.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  sudo ln -sfn ../jetson-enable-ssh.service "$wants_path"
}

maybe_preinstall_ssh_server() {
  local resolv_backup

  if [[ -x /usr/bin/qemu-aarch64-static ]]; then
    resolv_backup="$ROOTFS/etc/resolv.conf.codex-bak"
    if [[ -e "$ROOTFS/etc/resolv.conf" || -L "$ROOTFS/etc/resolv.conf" ]]; then
      sudo rm -f "$resolv_backup"
      sudo mv "$ROOTFS/etc/resolv.conf" "$resolv_backup"
    fi
    sudo cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
    for m in proc sys dev dev/pts; do
      sudo mount --bind "/$m" "$ROOTFS/$m"
    done
    sudo chroot "$ROOTFS" bash -c '
      set -e
      status="$(dpkg-query -W -f='"'"'${Status}'"'"' openssh-server 2>/dev/null || true)"
      if ! printf "%s" "$status" | grep -q "install ok installed"; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y || true
        apt-get install -y openssh-server || exit 0
      fi
      systemctl enable ssh || true
      rm -f /etc/ssh/ssh_host_*
    ' || true
    for m in dev/pts dev sys proc; do
      sudo umount -lf "$ROOTFS/$m" || true
    done
    sudo rm -f "$ROOTFS/etc/resolv.conf"
    if [[ -e "$resolv_backup" || -L "$resolv_backup" ]]; then
      sudo mv "$resolv_backup" "$ROOTFS/etc/resolv.conf"
    fi
  fi
}

seed_first_boot_ssh_service
maybe_preinstall_ssh_server

# --- set German keyboard system-wide in the target rootfs ---
# 1) System keyboard (affects TTY + GDM login)
sudo install -d "$ROOTFS/etc/default"
sudo tee "$ROOTFS/etc/default/keyboard" >/dev/null <<'EOF'
XKBMODEL="pc105"
XKBLAYOUT="de"
XKBVARIANT="nodeadkeys"
XKBOPTIONS=""
BACKSPACE="guess"
EOF
sudo tee "$ROOTFS/etc/default/locale" >/dev/null <<'EOF'
LANG=C.UTF-8
EOF

# 2) GNOME default input source for new users/login screen (can be changed later)
sudo install -d "$ROOTFS/etc/dconf/db/local.d" "$ROOTFS/etc/dconf/profile"
sudo tee "$ROOTFS/etc/dconf/profile/user" >/dev/null <<'EOF'
user-db:user
system-db:local
EOF
sudo tee "$ROOTFS/etc/dconf/db/local.d/00-keyboard" >/dev/null <<'EOF'
[org/gnome/desktop/input-sources]
sources=[('xkb', 'de+nodeadkeys')]
EOF

# 2b) Disable GNOME's first-login welcome flow in the flashed image.
disable_autostart_desktop_entry() {
  local desktop_path="$1"
  local desktop_name="$2"
  sudo tee "$desktop_path" >/dev/null <<EOF
[Desktop Entry]
Type=Application
Name=$desktop_name
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=false
EOF
}

sudo install -d "$ROOTFS/etc/xdg/autostart" "$ROOTFS/etc/skel/.config"
disable_autostart_desktop_entry \
  "$ROOTFS/etc/xdg/autostart/gnome-initial-setup-first-login.desktop" \
  "Initial Setup"
disable_autostart_desktop_entry \
  "$ROOTFS/etc/xdg/autostart/gnome-initial-setup-copy-worker.desktop" \
  "GNOME Initial Setup Copy Worker"
sudo touch "$ROOTFS/etc/skel/.config/gnome-initial-setup-done"

# 3) Try to compile dconf defaults + refresh keyboard inside the rootfs (optional)
maybe_chroot_config() {
  # Needs qemu-user-static + binfmt on the host
  if [[ -x /usr/bin/qemu-aarch64-static ]]; then
    # Bind mounts for dpkg/update-initramfs
    for m in proc sys dev dev/pts; do
      sudo mount --bind "/$m" "$ROOTFS/$m"
    done
    sudo chroot "$ROOTFS" /usr/bin/dconf update || true
    sudo chroot "$ROOTFS" bash -c '
      set -e
      echo "keyboard-configuration keyboard-configuration/layoutcode string de" | debconf-set-selections
      echo "keyboard-configuration keyboard-configuration/variantcode string nodeadkeys" | debconf-set-selections
      echo "keyboard-configuration keyboard-configuration/modelcode string pc105" | debconf-set-selections
      DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration || true
      update-initramfs -u || true
    ' || true
    # Clean up mounts
    for m in dev/pts dev sys proc; do
      sudo umount -lf "$ROOTFS/$m" || true
    done
  fi
}
maybe_chroot_config
# --- end keyboard preset ---


# ---------- Home script on target (NOT Desktop) ----------
HOME_SCRIPT_NAME="clone.sh"
HOME_SCRIPT_CONTENT='#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$HOME/git"
cd "$HOME/git"
if [[ ! -d Jetson ]]; then
  git clone https://github.com/robertZaufall/Jetson
fi
cd Jetson/src
chmod +x start.sh
'

# Seed for future users
SKEL_DIR="$ROOTFS/etc/skel"
sudo install -d "$SKEL_DIR"
echo "$HOME_SCRIPT_CONTENT" | sudo tee "$SKEL_DIR/$HOME_SCRIPT_NAME" >/dev/null
sudo chmod +x "$SKEL_DIR/$HOME_SCRIPT_NAME"

# Write into the actual default user's home if it already exists
if [[ -d "$USER_HOME_DIR" ]]; then
  sudo install -d "$USER_HOME_DIR/.config"
  echo "$HOME_SCRIPT_CONTENT" | sudo tee "$USER_HOME_DIR/$HOME_SCRIPT_NAME" >/dev/null
  sudo chmod +x "$USER_HOME_DIR/$HOME_SCRIPT_NAME"
  sudo touch "$USER_HOME_DIR/.config/gnome-initial-setup-done"
  # chown using UID:GID from target rootfs if available, else fall back to 1000:1000
  UID_GID=""
  if [[ -f "$ROOTFS/etc/passwd" ]]; then
    UID_GID="$(awk -F: -v u="$USER_NAME" '$1==u{print $3 ":" $4}' "$ROOTFS/etc/passwd" || true)"
  fi
  if [[ -n "${UID_GID:-}" ]]; then
    sudo chown "$UID_GID" "$USER_HOME_DIR/.config" "$USER_HOME_DIR/.config/gnome-initial-setup-done" "$USER_HOME_DIR/$HOME_SCRIPT_NAME" || true
  else
    sudo chown 1000:1000 "$USER_HOME_DIR/.config" "$USER_HOME_DIR/.config/gnome-initial-setup-done" "$USER_HOME_DIR/$HOME_SCRIPT_NAME" || true
  fi
fi

# ---------- Final reminder before flashing ----------

# Full flash to NVMe rootfs + QSPI (put device in Force-Recovery for first-time QSPI)
cd "$JETPACK"

#sudo ./tools/kernel_flash/l4t_initrd_flash.sh \
#  --external-device nvme0n1p1 \
#  -c tools/kernel_flash/flash_l4t_t264_nvme.xml \
#  --showlogs --network usb0 \
#  jetson-agx-thor-devkit external

sudo ./tools/kernel_flash/l4t_initrd_flash.sh \
  --showlogs --network usb0 \
  jetson-agx-thor-devkit internal
