# Yahboom Orin NX Wi-Fi Fix

This documents the post-flash Wi-Fi fix for a Yahboom Orin NX setup using JetPack 7.2 / Ubuntu 24.04 with kernel `6.8.12-1021-tegra`.

## Problem

The Intel 8265 / 8275 PCIe Wi-Fi card is detected, but no Wi-Fi device appears in NetworkManager:

```bash
lspci -nn | grep -i network
nmcli dev
modinfo iwlwifi
zgrep -E "CONFIG_IWLWIFI|CONFIG_IWLMVM|CONFIG_CFG80211|CONFIG_MAC80211" /proc/config.gz
```

Observed result:

```text
Intel Corporation Wireless 8265 / 8275 [8086:24fd]
modinfo: ERROR: Module iwlwifi not found.
# CONFIG_IWLWIFI is not set
```

`sudo apt install iwlwifi-modules -y` does not fix this on JetPack 7 because that package is not the right path for NVIDIA's Tegra kernel.

## Preferred Flash-Time Fix

The Orin NX flash script can reuse a known-good module build instead of rebuilding DKMS on every flash. This is valid while the target kernel stays the same:

```text
6.8.12-1021-tegra
```

Cached assets are stored in the repository:

```text
src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/
├── firmware/
│   ├── iwlwifi-8265-34.ucode
│   └── iwlwifi-8265-36.ucode
└── modules/
    ├── cfg80211.ko
    ├── iwlmvm.ko
    ├── iwlwifi-compat.ko
    ├── iwlwifi.ko
    ├── iwlxvt.ko
    └── mac80211.ko
```

`src/orin_nx.sh` applies these assets automatically by default before `l4t_initrd_flash.sh` builds the image:

```bash
bash src/orin_nx.sh <user> <pass> <hostname> --wifi-ssid=SSID --wifi-psk=PASS
```

The script copies modules into:

```text
rootfs/lib/modules/6.8.12-1021-tegra/updates/dkms/
```

copies firmware into:

```text
rootfs/etc/firmware/
```

and refreshes the target module metadata:

```bash
sudo depmod -b rootfs 6.8.12-1021-tegra
```

Before copying assets, the script checks that the target rootfs kernel has a matching cached asset directory, validates each cached module's `vermagic` against that kernel, and verifies `SHA256SUMS`. If any of those checks fail, flashing continues without the cached module patch and the image still contains the manual target-side repair script.

Validate the cached files with:

```bash
cd src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra
sha256sum -c SHA256SUMS
```

This patch is Orin NX-only. `src/orin_nano.sh` uses a separate SDK rootfs and does not apply it. To skip the patch for an Orin NX flash:

```bash
bash src/orin_nx.sh <user> <pass> <hostname> --skip-intel-wifi-fix
```

Rebuild or replace the cached assets only when the JetPack/Tegra kernel changes.

## Target-Side Fallback Script

`src/orin_nx.sh` always bakes this script into the Orin NX image:

```text
~/yahboom-orin-nx-wifi-fix.sh
/usr/local/sbin/yahboom-orin-nx-wifi-fix.sh
```

For a default user named `yahboom`, the home copy is `/home/yahboom/yahboom-orin-nx-wifi-fix.sh`.

Use it after first boot when the cached pre-flash assets were skipped because of a kernel-version mismatch:

```bash
~/yahboom-orin-nx-wifi-fix.sh
sudo reboot
```

The script runs the same DKMS flow documented below on the target itself:

```text
apt install backport-iwlwifi-dkms dkms build-essential linux-firmware zstd pciutils
remove BUILD_EXCLUSIVE_CONFIG and OBSOLETE_BY from dkms.conf
dkms build/install for "$(uname -r)"
copy uncompressed iwlwifi-8265 firmware into /etc/firmware
```

This fallback needs package access from the target, for example Ethernet, USB network with routing, or another temporary network path.

## Collecting Assets

After fixing one device with the DKMS method below, collect the reusable assets from the working Jetson:

```bash
mkdir -p src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/modules
mkdir -p src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/firmware

ssh jetson@192.168.55.1 \
  'tar -C /lib/modules/6.8.12-1021-tegra/updates/dkms -cf - \
    iwlwifi-compat.ko iwlwifi.ko iwlxvt.ko iwlmvm.ko mac80211.ko cfg80211.ko' \
  | tar -C src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/modules -xf -

ssh jetson@192.168.55.1 \
  'tar -C /etc/firmware -cf - iwlwifi-8265-36.ucode iwlwifi-8265-34.ucode' \
  | tar -C src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/firmware -xf -
```

## Post-Flash DKMS Fix

Use this when the cached assets are missing or the target kernel changed.

Install the Ubuntu DKMS backport package and build it for the running Tegra kernel:

```bash
sudo apt update
sudo apt install -y backport-iwlwifi-dkms dkms build-essential linux-firmware zstd
```

Ubuntu's DKMS config skips this build on kernels newer than `6.7.0`, assuming those kernels already include `iwlwifi`. NVIDIA's `6.8.12-1021-tegra` kernel does not, so remove the DKMS skip guards:

```bash
sudo cp -a /usr/src/backport-iwlwifi-11510/dkms.conf \
  /usr/src/backport-iwlwifi-11510/dkms.conf.orig

sudo sed -i '/^BUILD_EXCLUSIVE_CONFIG=/d;/^OBSOLETE_BY=/d' \
  /usr/src/backport-iwlwifi-11510/dkms.conf
```

Re-register, build, and install the module:

```bash
sudo dkms remove -m backport-iwlwifi -v 11510 --all || true
sudo dkms add -m backport-iwlwifi -v 11510
sudo dkms build -m backport-iwlwifi -v 11510 -k "$(uname -r)"
sudo dkms install -m backport-iwlwifi -v 11510 -k "$(uname -r)"
sudo depmod -a "$(uname -r)"
```

## Firmware

Jetson Linux boots with:

```text
firmware_class.path=/etc/firmware
```

The Intel firmware exists under `/lib/firmware`, but it is compressed as `.zst`. Copy uncompressed firmware into `/etc/firmware`:

```bash
sudo install -d /etc/firmware

for v in 36 34; do
  sudo zstd -dc "/lib/firmware/iwlwifi-8265-$v.ucode.zst" \
    | sudo tee "/etc/firmware/iwlwifi-8265-$v.ucode" >/dev/null
done
```

Reboot so the DKMS `cfg80211`, `mac80211`, `iwlwifi`, and `iwlmvm` modules load cleanly:

```bash
sudo reboot
```

## Verify

After reboot:

```bash
dkms status
modinfo iwlwifi | head
lspci -k -nn -s 0001:01:00.0
nmcli dev
dmesg | grep -Ei "iwlwifi|iwlmvm|firmware|8086|24fd" | tail -80
```

Expected signs:

```text
backport-iwlwifi/11510, 6.8.12-1021-tegra, aarch64: installed
Kernel driver in use: iwlwifi
wlP1p1s0          wifi      connected
```

The Wi-Fi interface name may differ, but it should be a `wifi` device in `nmcli dev`.
