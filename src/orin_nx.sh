#!/usr/bin/env bash

# Steps:
# 1. Validate the required default user, password, and hostname arguments.
# 2. Resolve the JetPack 7.2 Orin NX `Linux_for_Tegra` directory and target rootfs.
# 3. Apply NVIDIA binaries and run flash prerequisites in the JetPack workspace.
# 4. Pre-create the default user account and hostname in the target image.
# 5. Optionally inject a Wi-Fi profile into the target rootfs.
# 6. Patch Intel 8265 Wi-Fi support into the Orin NX rootfs before flashing.
# 7. Preinstall and enable the SSH server for the target, with a first-boot fallback.
# 8. Preseed a German keyboard layout for the system, GNOME, and GDM in the target rootfs.
# 9. Keep the target locale non-German so only the keyboard layout changes.
# 10. Suppress GNOME's first-login welcome flow in the target image.
# 11. Optionally enter the rootfs with qemu-user-static to compile dconf defaults and refresh keyboard settings.
# 12. Seed a `clone.sh` helper into `/etc/skel` and the default user's home directory.
# 13. Flash the Jetson Orin NX image with `l4t_initrd_flash.sh`.

set -euo pipefail

normalize_locale() {
  unset LANGUAGE
  unset LC_ADDRESS LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT
  unset LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
  unset LC_TELEPHONE LC_TIME
  export LANG=C.UTF-8
  export LC_ALL=C.UTF-8
}

normalize_locale

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
YAHBOOM_WIFI_ASSET_ROOT="$SCRIPT_DIR/assets/yahboom_orin_nx_wifi"

usage() {
  echo "Usage: $0 <default-user-name> <default-user-password> <default-hostname> [--wifi-ssid=SSID] [--wifi-psk=PASS] [--board=BOARD] [--skip-intel-wifi-fix]" >&2
  echo "Default board: jetson-orin-nano-devkit-super" >&2
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
ORIN_NX_BOARD="${ORIN_NX_BOARD:-jetson-orin-nano-devkit-super}"
ORIN_NX_INTEL_WIFI_FIX="${ORIN_NX_INTEL_WIFI_FIX:-1}"
shift 3

for arg in "$@"; do
  case "$arg" in
    --wifi-ssid=*)
      WIFI_SSID="${arg#*=}"
      ;;
    --wifi-psk=*|--wifi-password=*)
      WIFI_PSK="${arg#*=}"
      ;;
    --board=*|--orin-nx-board=*)
      ORIN_NX_BOARD="${arg#*=}"
      ;;
    --skip-intel-wifi-fix)
      ORIN_NX_INTEL_WIFI_FIX=0
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

JETPACK_VERSION="${JETPACK_VERSION:-7.2}"
export JETPACK="${JETPACK:-$HOME/nvidia/nvidia_sdk/JetPack_${JETPACK_VERSION}_Linux_JETSON_ORIN_NX_TARGETS/Linux_for_Tegra}"
ROOTFS="$JETPACK/rootfs"
USER_HOME_DIR="$ROOTFS/home/$USER_NAME"

if [[ ! -d "$JETPACK" ]]; then
  echo "Jetson Orin NX Linux_for_Tegra directory not found: $JETPACK" >&2
  exit 1
fi

cd "$JETPACK"
sudo ./tools/l4t_flash_prerequisites.sh
sudo ./apply_binaries.sh
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

patch_yahboom_orin_nx_intel_wifi() {
  local kernel_version asset_dir modules_dir firmware_dir target_modules_dir target_firmware_dir candidate asset_vermagic
  local -a modules firmware

  if [[ "$ORIN_NX_INTEL_WIFI_FIX" != "1" ]]; then
    echo "Skipping Yahboom Orin NX Intel 8265 Wi-Fi rootfs patch."
    return
  fi

  if [[ ! -d "$YAHBOOM_WIFI_ASSET_ROOT" ]]; then
    echo "Yahboom Orin NX Wi-Fi asset directory not found: $YAHBOOM_WIFI_ASSET_ROOT" >&2
    echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
    return
  fi

  kernel_version=""
  while IFS= read -r candidate; do
    if [[ -d "$YAHBOOM_WIFI_ASSET_ROOT/$candidate" ]]; then
      kernel_version="$candidate"
      break
    fi
  done < <(find "$ROOTFS/lib/modules" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r)

  if [[ -z "$kernel_version" ]]; then
    echo "No cached Yahboom Orin NX Wi-Fi asset matches the target rootfs kernel." >&2
    echo "Available target kernels:" >&2
    find "$ROOTFS/lib/modules" -mindepth 1 -maxdepth 1 -type d -printf '  %f\n' | sort >&2 || true
    echo "Available cached assets:" >&2
    find "$YAHBOOM_WIFI_ASSET_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '  %f\n' | sort >&2 || true
    echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
    return
  fi

  asset_dir="$YAHBOOM_WIFI_ASSET_ROOT/$kernel_version"
  modules_dir="$asset_dir/modules"
  firmware_dir="$asset_dir/firmware"
  target_modules_dir="$ROOTFS/lib/modules/$kernel_version/updates/dkms"
  target_firmware_dir="$ROOTFS/etc/firmware"
  modules=(iwlwifi-compat.ko iwlwifi.ko iwlxvt.ko iwlmvm.ko mac80211.ko cfg80211.ko)
  firmware=(iwlwifi-8265-36.ucode iwlwifi-8265-34.ucode)

  for candidate in "${modules[@]}"; do
    if [[ ! -f "$modules_dir/$candidate" ]]; then
      echo "Missing cached Wi-Fi module asset: $modules_dir/$candidate" >&2
      echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
      return
    fi
  done
  for candidate in "${firmware[@]}"; do
    if [[ ! -f "$firmware_dir/$candidate" ]]; then
      echo "Missing cached Wi-Fi firmware asset: $firmware_dir/$candidate" >&2
      echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
      return
    fi
  done
  if ! command -v modinfo >/dev/null 2>&1; then
    echo "modinfo is required on the flash host to validate cached Wi-Fi modules." >&2
    echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
    return
  fi
  for candidate in "${modules[@]}"; do
    asset_vermagic="$(modinfo -F vermagic "$modules_dir/$candidate" 2>/dev/null || true)"
    if [[ "$asset_vermagic" != "$kernel_version "* ]]; then
      echo "Cached Wi-Fi module does not match the target rootfs kernel: $modules_dir/$candidate" >&2
      echo "  target kernel: $kernel_version" >&2
      echo "  module vermagic: ${asset_vermagic:-unknown}" >&2
      echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
      return
    fi
  done
  if [[ -f "$asset_dir/SHA256SUMS" ]]; then
    if ! (cd "$asset_dir" && sha256sum -c SHA256SUMS); then
      echo "Cached Wi-Fi asset checksum validation failed." >&2
      echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
      return
    fi
  fi
  if ! command -v depmod >/dev/null 2>&1; then
    echo "depmod is required on the flash host to patch the Orin NX rootfs." >&2
    echo "Continuing without pre-flash Wi-Fi module patch; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing." >&2
    return
  fi

  echo "Patching Yahboom Orin NX Intel 8265 Wi-Fi assets for kernel $kernel_version"
  sudo install -d "$target_modules_dir" "$target_firmware_dir"
  for candidate in "${modules[@]}"; do
    sudo install -m 0644 "$modules_dir/$candidate" "$target_modules_dir/$candidate"
  done
  for candidate in "${firmware[@]}"; do
    sudo install -m 0644 "$firmware_dir/$candidate" "$target_firmware_dir/$candidate"
  done
  if ! sudo depmod -b "$ROOTFS" "$kernel_version"; then
    echo "depmod failed for the patched Orin NX rootfs." >&2
    echo "Continuing with flash; run ~/yahboom-orin-nx-wifi-fix.sh on the target after flashing if Wi-Fi is missing." >&2
    return
  fi
}

patch_yahboom_orin_nx_intel_wifi

seed_yahboom_orin_nx_wifi_fix_script() {
  local script_name script_path skel_path user_script_path uid_gid

  script_name="yahboom-orin-nx-wifi-fix.sh"
  script_path="$ROOTFS/usr/local/sbin/$script_name"
  skel_path="$ROOTFS/etc/skel/$script_name"
  user_script_path="$USER_HOME_DIR/$script_name"

  sudo install -d "$ROOTFS/usr/local/sbin" "$ROOTFS/etc/skel"
  sudo tee "$script_path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

unset LANGUAGE
unset LC_ADDRESS LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT
unset LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
unset LC_TELEPHONE LC_TIME
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

kernel_version="$(uname -r)"
echo "Target kernel: $kernel_version"

if ! lspci -nn 2>/dev/null | grep -qi '8086:24fd'; then
  echo "Warning: Intel 8265 / 8275 PCI device [8086:24fd] was not detected." >&2
fi

if [[ ! -e "/lib/modules/$kernel_version/build/Makefile" ]]; then
  echo "Kernel headers for $kernel_version are missing." >&2
  echo "Install the matching linux-headers package before running this script." >&2
  exit 1
fi

"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y backport-iwlwifi-dkms dkms build-essential linux-firmware zstd pciutils

dkms_src_dir="$(find /usr/src -maxdepth 1 -type d -name 'backport-iwlwifi-*' | sort -V | tail -n 1)"
if [[ -z "$dkms_src_dir" ]]; then
  echo "backport-iwlwifi DKMS source directory was not found under /usr/src." >&2
  exit 1
fi

dkms_version="$(basename "$dkms_src_dir" | sed 's/^backport-iwlwifi-//')"
if [[ -z "$dkms_version" ]]; then
  echo "Could not determine backport-iwlwifi DKMS version from $dkms_src_dir." >&2
  exit 1
fi

if [[ ! -f "$dkms_src_dir/dkms.conf.orig" ]]; then
  "${SUDO[@]}" cp -a "$dkms_src_dir/dkms.conf" "$dkms_src_dir/dkms.conf.orig"
fi
"${SUDO[@]}" sed -i '/^BUILD_EXCLUSIVE_CONFIG=/d;/^OBSOLETE_BY=/d' "$dkms_src_dir/dkms.conf"

"${SUDO[@]}" dkms remove -m backport-iwlwifi -v "$dkms_version" --all || true
"${SUDO[@]}" dkms add -m backport-iwlwifi -v "$dkms_version"
"${SUDO[@]}" dkms build -m backport-iwlwifi -v "$dkms_version" -k "$kernel_version"
"${SUDO[@]}" dkms install -m backport-iwlwifi -v "$dkms_version" -k "$kernel_version"
"${SUDO[@]}" depmod -a "$kernel_version"

"${SUDO[@]}" install -d /etc/firmware
for version in 36 34; do
  firmware_name="iwlwifi-8265-$version.ucode"
  compressed_path="/lib/firmware/$firmware_name.zst"
  plain_path="/lib/firmware/$firmware_name"
  tmp_path="$(mktemp)"

  if [[ -f "$compressed_path" ]]; then
    zstd -dc "$compressed_path" >"$tmp_path"
  elif [[ -f "$plain_path" ]]; then
    cp "$plain_path" "$tmp_path"
  else
    rm -f "$tmp_path"
    echo "Missing firmware source for $firmware_name" >&2
    exit 1
  fi

  "${SUDO[@]}" install -m 0644 "$tmp_path" "/etc/firmware/$firmware_name"
  rm -f "$tmp_path"
done

echo "Intel Wi-Fi modules and firmware are installed."
echo "Reboot before final verification so the DKMS cfg80211/mac80211 stack loads cleanly."
echo
echo "After reboot, verify with:"
echo "  dkms status"
echo "  lspci -k -nn | grep -A4 -Ei 'network controller|8086|24fd'"
echo "  nmcli dev"
EOF
  sudo chmod 755 "$script_path"
  sudo install -m 0755 "$script_path" "$skel_path"

  if [[ -d "$USER_HOME_DIR" ]]; then
    sudo install -m 0755 "$script_path" "$user_script_path"
    uid_gid=""
    if [[ -f "$ROOTFS/etc/passwd" ]]; then
      uid_gid="$(awk -F: -v u="$USER_NAME" '$1==u{print $3 ":" $4}' "$ROOTFS/etc/passwd" || true)"
    fi
    if [[ -n "${uid_gid:-}" ]]; then
      sudo chown "$uid_gid" "$user_script_path" || true
    else
      sudo chown 1000:1000 "$user_script_path" || true
    fi
  fi
}

seed_yahboom_orin_nx_wifi_fix_script

seed_first_boot_ssh_service() {
  local script_path service_path wants_path

  script_path="$ROOTFS/usr/local/sbin/jetson-enable-ssh.sh"
  service_path="$ROOTFS/etc/systemd/system/jetson-enable-ssh.service"
  wants_path="$ROOTFS/etc/systemd/system/multi-user.target.wants/jetson-enable-ssh.service"

  sudo install -d "$ROOTFS/usr/local/sbin" "$ROOTFS/etc/systemd/system" "$ROOTFS/etc/systemd/system/multi-user.target.wants"
  sudo tee "$script_path" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

unset LANGUAGE
unset LC_ADDRESS LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT
unset LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
unset LC_TELEPHONE LC_TIME
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

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
  local resolv_backup m idx
  local -a mounted=()

  cleanup_preinstall_ssh() {
    for ((idx=${#mounted[@]} - 1; idx >= 0; idx--)); do
      sudo umount -lf "$ROOTFS/${mounted[$idx]}" || true
    done
    sudo rm -f "$ROOTFS/etc/resolv.conf"
    if [[ -e "$resolv_backup" || -L "$resolv_backup" ]]; then
      sudo mv "$resolv_backup" "$ROOTFS/etc/resolv.conf"
    fi
  }

  if [[ -x /usr/bin/qemu-aarch64-static ]]; then
    resolv_backup="$ROOTFS/etc/resolv.conf.codex-bak"
    trap cleanup_preinstall_ssh RETURN
    if [[ -e "$ROOTFS/etc/resolv.conf" || -L "$ROOTFS/etc/resolv.conf" ]]; then
      sudo rm -f "$resolv_backup"
      sudo mv "$ROOTFS/etc/resolv.conf" "$resolv_backup"
    fi
    sudo cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
    for m in proc sys dev dev/pts; do
      sudo mount --bind "/$m" "$ROOTFS/$m"
      mounted+=("$m")
    done
    sudo env -u LANGUAGE LANG=C.UTF-8 LC_ALL=C.UTF-8 chroot "$ROOTFS" bash -c '
      set -e
      unset LC_ADDRESS LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT
      unset LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
      unset LC_TELEPHONE LC_TIME
      status="$(dpkg-query -W -f='"'"'${Status}'"'"' openssh-server 2>/dev/null || true)"
      if ! printf "%s" "$status" | grep -q "install ok installed"; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y || true
        apt-get install -y openssh-server || exit 0
      fi
      systemctl enable ssh || true
      rm -f /etc/ssh/ssh_host_*
    ' || true
    trap - RETURN
    cleanup_preinstall_ssh
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
LC_ALL=C.UTF-8
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
    local m idx
    local -a mounted=()
    cleanup_chroot_config() {
      for ((idx=${#mounted[@]} - 1; idx >= 0; idx--)); do
        sudo umount -lf "$ROOTFS/${mounted[$idx]}" || true
      done
    }
    trap cleanup_chroot_config RETURN

    # Bind mounts for dpkg/update-initramfs
    for m in proc sys dev dev/pts; do
      sudo mount --bind "/$m" "$ROOTFS/$m"
      mounted+=("$m")
    done
    sudo env -u LANGUAGE LANG=C.UTF-8 LC_ALL=C.UTF-8 chroot "$ROOTFS" /usr/bin/dconf update || true
    sudo env -u LANGUAGE LANG=C.UTF-8 LC_ALL=C.UTF-8 chroot "$ROOTFS" bash -c '
      set -e
      unset LC_ADDRESS LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT
      unset LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
      unset LC_TELEPHONE LC_TIME
      echo "keyboard-configuration keyboard-configuration/layoutcode string de" | debconf-set-selections
      echo "keyboard-configuration keyboard-configuration/variantcode string nodeadkeys" | debconf-set-selections
      echo "keyboard-configuration keyboard-configuration/modelcode string pc105" | debconf-set-selections
      DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration || true
      update-initramfs -u || true
    ' || true
    trap - RETURN
    cleanup_chroot_config
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
FLASH_SCRIPT="./l4t_initrd_flash.sh"
if [[ ! -x "$FLASH_SCRIPT" ]]; then
  FLASH_SCRIPT="./tools/kernel_flash/l4t_initrd_flash.sh"
fi
echo "Flashing Jetson Orin NX with board config: $ORIN_NX_BOARD"
sudo "$FLASH_SCRIPT" \
  --showlogs --erase-all \
  "$ORIN_NX_BOARD" internal
echo "Flash command completed successfully."
exit 0
