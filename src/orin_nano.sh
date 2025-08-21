#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <default-user-name> <default-user-password> <default-hostname>" >&2
  exit 1
fi

USER_NAME="$1"
export JETPACK="$HOME/nvidia/nvidia_sdk/JetPack_6.2.1_Linux_JETSON_ORIN_NANO_TARGETS/Linux_for_Tegra"
ROOTFS="$JETPACK/rootfs"

cd "$JETPACK"
sudo ./apply_binaries.sh
sudo ./tools/l4t_flash_prerequisites.sh
sudo ./tools/l4t_create_default_user.sh -u "$1" -p "$2" -a -n "$3" --accept-license

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
USER_HOME_DIR="$ROOTFS/home/$USER_NAME"
if [[ -d "$USER_HOME_DIR" ]]; then
  echo "$HOME_SCRIPT_CONTENT" | sudo tee "$USER_HOME_DIR/$HOME_SCRIPT_NAME" >/dev/null
  sudo chmod +x "$USER_HOME_DIR/$HOME_SCRIPT_NAME"
  # chown using UID:GID from target rootfs if available, else fall back to 1000:1000
  UID_GID=""
  if [[ -f "$ROOTFS/etc/passwd" ]]; then
    UID_GID="$(awk -F: -v u="$USER_NAME" '$1==u{print $3 ":" $4}' "$ROOTFS/etc/passwd" || true)"
  fi
  if [[ -n "${UID_GID:-}" ]]; then
    sudo chown "$UID_GID" "$USER_HOME_DIR/$HOME_SCRIPT_NAME" || true
  else
    sudo chown 1000:1000 "$USER_HOME_DIR/$HOME_SCRIPT_NAME" || true
  fi
fi

# ---------- Final reminder before flashing ----------

# Full flash to NVMe rootfs + QSPI (put device in Force-Recovery for first-time QSPI)
cd "$JETPACK"
sudo ./tools/kernel_flash/l4t_initrd_flash.sh \
  --external-device nvme0n1p1 \
  -c tools/kernel_flash/flash_l4t_t234_nvme.xml \
  -p "-c bootloader/generic/cfg/flash_t234_qspi.xml" \
  --showlogs --network usb0 \
  jetson-orin-nano-devkit-super internal
