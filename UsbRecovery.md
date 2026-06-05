# USB Recovery Access

This documents the USB access path used after flashing when the Jetson was still connected to the host by USB, Wi-Fi was unavailable, and SSH was not initially reachable.

## What the USB Link Provides

Jetson Linux exposes a USB device-mode network interface to the host. In this setup the host received `192.168.55.100/24`, and the Jetson was reachable at:

```bash
192.168.55.1
```

Check the host side:

```bash
ip -br addr
ip route
lsusb
nmcli device status
```

Expected signs:

```text
NVIDIA Corp. L4T (Linux for Tegra) running on Tegra
192.168.55.0/24 dev <usb-interface>
```

Then test the target:

```bash
ping -c 1 -W 2 192.168.55.1
nc -vz -w 3 192.168.55.1 22
```

If ping works but port 22 is refused, the USB network is working and SSH is not running on the Jetson.

## Serial Console Fallback

The USB cable also exposed a serial console as `/dev/ttyACM0` on the host:

```bash
ls -l /dev/serial/by-id /dev/ttyACM* /dev/ttyUSB*
```

Connect at 115200 baud. If `busybox` is available:

```bash
sudo busybox microcom -s 115200 /dev/ttyACM0
```

Log in with the default user and password created by the flash script.

## Enable SSH on the Jetson

From the serial console:

```bash
sudo systemctl enable --now ssh
systemctl is-active ssh
```

If SSH host keys are missing, regenerate them:

```bash
sudo ssh-keygen -A
sudo systemctl restart ssh
```

After that, the host should see port 22:

```bash
nc -vz -w 3 192.168.55.1 22
```

Connect over USB Ethernet:

```bash
ssh <user>@192.168.55.1
```

## Useful Checks After Login

```bash
hostname
uname -a
nvpmodel -q
nmcli device status
lspci -nn
```

For the Wi-Fi issue we saw, the Intel card was visible on PCIe, but no Wi-Fi network device appeared because the `iwlwifi` kernel module was absent:

```bash
lspci -k -nn -s 0001:01:00.0
modinfo iwlwifi
zgrep -E "CONFIG_IWLWIFI|CONFIG_IWLMVM|CONFIG_CFG80211|CONFIG_MAC80211" /proc/config.gz
```

The important result was:

```text
# CONFIG_IWLWIFI is not set
modinfo: ERROR: Module iwlwifi not found.
```

That means the USB connection and NetworkManager profile are not the Wi-Fi blocker; the flashed kernel image lacks the Intel Wi-Fi driver.
