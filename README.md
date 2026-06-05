# Jetson

[Installation](Installation.md)  
[ROS](ROS.md)  
[Jetson Containers](JetsonContainers.md)  
[Registry and Mirrors](Registry.md)  
[K3s](K3s.md)  
[USB Recovery Access](UsbRecovery.md)  
[Yahboom Orin NX Wi-Fi Fix](yahboom_orin_nx_wifi_fix.md)  

## Yahboom Orin NX Wi-Fi

The Yahboom Orin NX carrier used here has an Intel 8265 / 8275 Wi-Fi card. JetPack 7.2 ships the `6.8.12-1021-tegra` kernel without `iwlwifi`, so the Orin NX flash helper patches cached, prebuilt Intel Wi-Fi modules into the NX rootfs before flashing.

The cached assets live under:

```text
src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/
```

`src/orin_nx.sh` applies those assets automatically by default and runs `depmod` in the target rootfs. Before copying files, it verifies that the cached asset directory matches the target rootfs kernel, validates the cached module `vermagic`, and checks `SHA256SUMS`.

If the cached assets do not match the image kernel, the script continues flashing and bakes a manual target-side repair script into the image:

```text
~/yahboom-orin-nx-wifi-fix.sh
/usr/local/sbin/yahboom-orin-nx-wifi-fix.sh
```

Run it on the Jetson after first boot if the prebuilt modules were skipped:

```bash
~/yahboom-orin-nx-wifi-fix.sh
sudo reboot
```

`src/orin_nano.sh` does not apply this patch and uses its separate Orin Nano SDK rootfs. To skip the NX Wi-Fi patch explicitly:

```bash
bash src/orin_nx.sh <user> <pass> <hostname> --skip-intel-wifi-fix
```

See [Yahboom Orin NX Wi-Fi Fix](yahboom_orin_nx_wifi_fix.md) for the post-flash DKMS build, firmware details, and the cached-asset flashing flow.
