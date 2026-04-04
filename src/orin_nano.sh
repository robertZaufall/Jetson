#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <default-user-name> <default-user-password> <default-hostname>" >&2
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
JETPACK_TARGET="JETSON_ORIN_NANO"

resolve_jetpack_dir() {
  local jetpack_pattern matches=()

  jetpack_pattern="$HOME/nvidia/nvidia_sdk/JetPack_6.*_Linux_${JETPACK_TARGET}_TARGETS/Linux_for_Tegra"
  mapfile -t matches < <(compgen -G "$jetpack_pattern" | sort -V)

  if [[ "${#matches[@]}" -eq 0 ]]; then
    echo "Could not find a JetPack 6 Linux_for_Tegra directory matching: $jetpack_pattern" >&2
    exit 1
  fi

  printf '%s\n' "${matches[${#matches[@]}-1]}"
}

JETPACK="$(resolve_jetpack_dir)"
ROOTFS="$JETPACK/rootfs"
USER_HOME_DIR="$ROOTFS/home/$USER_NAME"

cd "$JETPACK"
sudo ./apply_binaries.sh
sudo ./tools/l4t_flash_prerequisites.sh
sudo ./tools/l4t_create_default_user.sh -u "$USER_NAME" -p "$USER_PASSWORD" -a -n "$TARGET_HOSTNAME" --accept-license

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

# Keep the flashed system in English while preserving the German keyboard layout.
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

sudo install -d "$ROOTFS/etc/dconf/db/local.d" "$ROOTFS/etc/dconf/profile"
sudo tee "$ROOTFS/etc/dconf/profile/user" >/dev/null <<'EOF'
user-db:user
system-db:local
EOF
sudo tee "$ROOTFS/etc/dconf/db/local.d/00-keyboard" >/dev/null <<'EOF'
[org/gnome/desktop/input-sources]
sources=[('xkb', 'de+nodeadkeys')]
EOF

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

maybe_chroot_config() {
  if [[ -x /usr/bin/qemu-aarch64-static ]]; then
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
    for m in dev/pts dev sys proc; do
      sudo umount -lf "$ROOTFS/$m" || true
    done
  fi
}
maybe_chroot_config

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

SKEL_DIR="$ROOTFS/etc/skel"
sudo install -d "$SKEL_DIR"
echo "$HOME_SCRIPT_CONTENT" | sudo tee "$SKEL_DIR/$HOME_SCRIPT_NAME" >/dev/null
sudo chmod +x "$SKEL_DIR/$HOME_SCRIPT_NAME"

if [[ -d "$USER_HOME_DIR" ]]; then
  sudo install -d "$USER_HOME_DIR/.config"
  echo "$HOME_SCRIPT_CONTENT" | sudo tee "$USER_HOME_DIR/$HOME_SCRIPT_NAME" >/dev/null
  sudo chmod +x "$USER_HOME_DIR/$HOME_SCRIPT_NAME"
  sudo touch "$USER_HOME_DIR/.config/gnome-initial-setup-done"

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

cd "$JETPACK"
sudo ./tools/kernel_flash/l4t_initrd_flash.sh \
  --external-device nvme0n1p1 \
  -c tools/kernel_flash/flash_l4t_t234_nvme.xml \
  -p "-c bootloader/generic/cfg/flash_t234_qspi.xml" \
  --showlogs --network usb0 \
  jetson-orin-nano-devkit-super internal
